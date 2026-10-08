//! Error types for the seismic rpc api.

use std::convert::Infallible;

use alloy_rpc_types_eth::BlockError;
use reth_provider::ProviderError;
use reth_rpc_eth_api::{AsEthApiError, EthTxEnvError, TransactionConversionError};
use reth_rpc_eth_types::{error::api::FromEvmHalt, EthApiError, RpcInvalidTransactionError};
use reth_rpc_server_types::result::{internal_rpc_err, rpc_error_with_code};
use revm::context_interface::result::EVMError;
use revm_context::result::HaltReason;

#[derive(Debug, thiserror::Error)]
/// Seismic API error
pub enum SeismicEthApiError {
    /// Eth error
    #[error(transparent)]
    Eth(EthApiError),
    /// Enclave error
    #[error("enclave error: {0}")]
    EnclaveError(String),
}

/// Strip the attached gas limit from estimation/simulation errors while preserving the
/// upstream message prefix and error code that clients match on.
///
/// The estimator caps the simulated gas limit at the caller's allowance before executing
/// (`estimate.rs`), so whenever one of these errors fires because the allowance was the
/// binding limit, the attached number *is* `floor((balance * divisor - fee) / price)`: the
/// caller's native or registry-token balance at the signed gas price. Signed-read responses
/// are encrypted to the signer, but only `Revert` outputs are re-encrypted; these errors
/// would otherwise reach whoever relayed the signed read in plaintext.
fn redact_gas_limit(error: RpcInvalidTransactionError) -> EthApiError {
    let message = match &error {
        RpcInvalidTransactionError::GasRequiredExceedsAllowance { .. } => {
            "gas required exceeds allowance"
        }
        RpcInvalidTransactionError::BasicOutOfGas(_) |
        RpcInvalidTransactionError::MemoryOutOfGas(_) |
        RpcInvalidTransactionError::PrecompileOutOfGas(_) |
        RpcInvalidTransactionError::InvalidOperandOutOfGas(_) => {
            "out of gas: gas required exceeds the simulated gas limit"
        }
        _ => return EthApiError::InvalidTransaction(error),
    };
    // Keep the variant's own code (-32000 for allowance, -32003 for out of gas).
    EthApiError::InvalidTransaction(RpcInvalidTransactionError::other(rpc_error_with_code(
        error.error_code(),
        message,
    )))
}

impl From<EthApiError> for SeismicEthApiError {
    fn from(error: EthApiError) -> Self {
        // Some shared simulation/block helpers convert revm errors before returning
        // to this API. Redact that route too, not only direct EVM/allowance errors.
        // Auto can choose a private token, so never assume these amounts are native.
        match error {
            EthApiError::InvalidTransaction(RpcInvalidTransactionError::InsufficientFunds {
                ..
            }) => Self::Eth(crate::eth::payment::insufficient_payment()),
            // Allowance-capped gas limits are balance-derived; see `redact_gas_limit`.
            EthApiError::InvalidTransaction(error) => Self::Eth(redact_gas_limit(error)),
            error => Self::Eth(error),
        }
    }
}

impl AsEthApiError for SeismicEthApiError {
    fn as_err(&self) -> Option<&EthApiError> {
        match self {
            Self::Eth(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SeismicEthApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: SeismicEthApiError) -> Self {
        match error {
            SeismicEthApiError::Eth(e) => e.into(),
            SeismicEthApiError::EnclaveError(e) => internal_rpc_err(format!("enclave error: {e}")),
        }
    }
}

impl From<TransactionConversionError> for SeismicEthApiError {
    fn from(value: TransactionConversionError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<EthTxEnvError> for SeismicEthApiError {
    fn from(value: EthTxEnvError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<ProviderError> for SeismicEthApiError {
    fn from(value: ProviderError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<BlockError> for SeismicEthApiError {
    fn from(value: BlockError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<Infallible> for SeismicEthApiError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<EVMError<ProviderError>> for SeismicEthApiError {
    fn from(error: EVMError<ProviderError>) -> Self {
        match error {
            EVMError::Transaction(error) => Self::Eth(crate::eth::payment::invalid_payment(error)),
            error => Self::Eth(EthApiError::from(error)),
        }
    }
}

// Implementation for revm halt reason (base case)
impl From<HaltReason> for SeismicEthApiError {
    fn from(halt: HaltReason) -> Self {
        Self::Eth(EthApiError::other(internal_rpc_err(format!("EVM halted: {halt:?}"))))
    }
}

// FromEvmHalt implementation for base revm halt reason
impl FromEvmHalt<HaltReason> for SeismicEthApiError {
    fn from_evm_halt(halt: HaltReason, _gas_limit: u64) -> Self {
        // The estimator passes its allowance-capped simulation gas limit here, which is
        // balance-derived when the allowance binds. The halt reason alone carries no amounts.
        Self::from(halt)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::SeismicEthApiError;

    #[test]
    fn payment_amounts_are_redacted_from_direct_and_block_simulation_errors() {
        use alloy_primitives::{B256, U256};
        use reth_evm::block::{BlockExecutionError, BlockValidationError};
        use reth_provider::ProviderError;
        use reth_rpc_eth_types::{EthApiError, RpcInvalidTransactionError};
        use revm::context_interface::result::{EVMError, InvalidTransaction};
        let reason = InvalidTransaction::LackOfFundForMaxFee {
            fee: Box::new(U256::from(987_654_321)),
            balance: Box::new(U256::from(123_456_789)),
        };
        let block_error: EthApiError =
            BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                hash: B256::ZERO,
                error: Box::new(reason.clone()),
            })
            .into();
        let direct: EVMError<ProviderError> = EVMError::Transaction(reason);
        for error in [SeismicEthApiError::from(direct), SeismicEthApiError::from(block_error)] {
            assert!(matches!(
                error,
                SeismicEthApiError::Eth(EthApiError::InvalidTransaction(
                    RpcInvalidTransactionError::SeismicTx(_)
                ))
            ));
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("987654321"));
                assert!(!text.contains("123456789"));
            }
            let wire: jsonrpsee::types::ErrorObjectOwned = error.into();
            assert_ne!(wire.code(), -32603);
            assert!(wire.data().is_none());
            assert!(!wire.message().contains("123456789"));
        }
    }

    #[test]
    fn pool_gas_limit_data_survives_seismic_rpc_conversion() {
        use alloy_primitives::B256;
        use reth_rpc_eth_types::EthApiError;
        use reth_transaction_pool::error::{
            GasLimitReason, InvalidPoolTransactionError, PoolError,
        };

        let pool = PoolError::new(
            B256::ZERO,
            InvalidPoolTransactionError::GasLimitBelowMinimum {
                gas_limit: 21_480,
                minimum_gas_limit: 21_800,
                reason: GasLimitReason::CalldataFloor,
            },
        );
        let wire: jsonrpsee::types::ErrorObjectOwned =
            SeismicEthApiError::from(EthApiError::from(pool)).into();
        assert_eq!(wire.code(), -32000);
        assert_eq!(wire.message(), "intrinsic gas too low");
        assert_eq!(
            wire.data().map(|data| data.get()),
            Some(r#"{"gasLimit":"0x53e8","minimumGasLimit":"0x5528","reason":"calldataFloor"}"#)
        );
    }

    #[test]
    fn execution_gas_errors_remain_data_less_in_seismic_rpc() {
        use alloy_primitives::B256;
        use reth_evm::block::{BlockExecutionError, BlockValidationError};
        use reth_provider::ProviderError;
        use reth_rpc_eth_types::EthApiError;
        use revm::context_interface::result::{EVMError, InvalidTransaction};

        for reason in [
            InvalidTransaction::CallGasCostMoreThanGasLimit {
                initial_gas: 123_456,
                gas_limit: 21_000,
            },
            InvalidTransaction::GasFloorMoreThanGasLimit { gas_floor: 987_654, gas_limit: 21_000 },
        ] {
            let block_error: EthApiError =
                BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    hash: B256::ZERO,
                    error: Box::new(reason.clone()),
                })
                .into();
            let direct = EVMError::<ProviderError>::Transaction(reason);
            for error in [SeismicEthApiError::from(direct), SeismicEthApiError::from(block_error)] {
                let wire: jsonrpsee::types::ErrorObjectOwned = error.into();
                assert_eq!(wire.code(), -32000);
                assert_eq!(wire.message(), "intrinsic gas too low");
                assert!(wire.data().is_none());
            }
        }
    }

    /// The estimator caps its simulation gas limit at the caller's allowance, so the gas
    /// limit attached to these errors can be `floor((balance * divisor - fee) / price)`.
    /// Unlike `Revert` outputs, errors are not re-encrypted on the signed-read path.
    #[test]
    fn allowance_capped_gas_limits_are_redacted_but_keep_codes_and_prefixes() {
        use reth_rpc_eth_api::FromEthApiError;
        use reth_rpc_eth_types::{
            error::api::FromEvmHalt, EthApiError, RpcInvalidTransactionError,
        };
        use revm_context::result::{HaltReason, OutOfGasError};

        // A six-decimal balance of 123_456_789 raw units at 1 gwei: (balance * 1e12) / 1e9.
        const ALLOWANCE: u64 = 123_456_789_000;
        let marker = ALLOWANCE.to_string();

        type Fixture = fn() -> RpcInvalidTransactionError;
        let cases: [(Fixture, i32, &str); 3] = [
            (
                || RpcInvalidTransactionError::GasRequiredExceedsAllowance { gas_limit: ALLOWANCE },
                -32000,
                "gas required exceeds allowance",
            ),
            (
                || RpcInvalidTransactionError::BasicOutOfGas(ALLOWANCE),
                -32003,
                "out of gas: gas required exceeds",
            ),
            (
                || RpcInvalidTransactionError::MemoryOutOfGas(ALLOWANCE),
                -32003,
                "out of gas: gas required exceeds",
            ),
        ];
        for (upstream, code, prefix) in cases {
            assert!(upstream().to_string().contains(&marker), "fixture must carry the amount");
            // Both estimator routes: `into_eth_err()` -> `from_eth_err` -> `From<EthApiError>`.
            for error in [
                SeismicEthApiError::from_eth_err(upstream()),
                SeismicEthApiError::from(EthApiError::from(upstream())),
            ] {
                for text in [error.to_string(), format!("{error:?}")] {
                    assert!(!text.contains(&marker), "amount leaked: {text}");
                }
                let wire: jsonrpsee::types::ErrorObjectOwned = error.into();
                assert_eq!(wire.code(), code);
                assert!(wire.message().starts_with(prefix), "{}", wire.message());
                assert!(!wire.message().contains(&marker));
                assert!(wire.data().is_none());
            }
        }

        // The halt route receives the same allowance-capped simulation gas limit.
        for halt in [
            HaltReason::OutOfGas(OutOfGasError::Basic),
            HaltReason::OutOfGas(OutOfGasError::Memory),
            HaltReason::OpcodeNotFound,
        ] {
            let error = SeismicEthApiError::from_evm_halt(halt, ALLOWANCE);
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains(&marker), "amount leaked: {text}");
            }
            let wire: jsonrpsee::types::ErrorObjectOwned = error.into();
            assert!(wire.message().starts_with("EVM halted: "), "{}", wire.message());
            assert!(!wire.message().contains(&marker));
            assert!(wire.data().is_none());
        }

        // Unrelated invalid-transaction errors pass through untouched.
        let nonce: EthApiError = RpcInvalidTransactionError::NonceTooLow { tx: 1, state: 2 }.into();
        let expected = nonce.to_string();
        assert_eq!(SeismicEthApiError::from(nonce).to_string(), expected);
    }

    #[test]
    fn enclave_error_message() {
        let err: jsonrpsee::types::error::ErrorObject<'static> =
            SeismicEthApiError::EnclaveError("test".to_string()).into();
        assert_eq!(err.message(), "enclave error: test");
    }
}
