//! Error types for the seismic rpc api.

use std::convert::Infallible;

use alloy_rpc_types_eth::BlockError;
use reth_provider::ProviderError;
use reth_rpc_eth_api::{AsEthApiError, EthTxEnvError, TransactionConversionError};
use reth_rpc_eth_types::{error::api::FromEvmHalt, EthApiError};
use reth_rpc_server_types::result::internal_rpc_err;
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

impl From<EthApiError> for SeismicEthApiError {
    fn from(error: EthApiError) -> Self {
        // Some shared simulation/block helpers convert revm errors before returning
        // to this API. Redact that route too, not only direct EVM/allowance errors.
        // Auto can choose a private token, so never assume these amounts are native.
        match error {
            EthApiError::InvalidTransaction(
                reth_rpc_eth_types::RpcInvalidTransactionError::InsufficientFunds { .. },
            ) => Self::Eth(crate::eth::payment::insufficient_payment()),
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
    fn from_evm_halt(halt: HaltReason, gas_limit: u64) -> Self {
        // Delegate to the existing From implementation for the halt reason
        // and use the gas limit info if needed
        Self::Eth(EthApiError::other(internal_rpc_err(format!(
            "EVM halted: {halt:?} (gas limit: {gas_limit})"
        ))))
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
    fn enclave_error_message() {
        let err: jsonrpsee::types::error::ErrorObject<'static> =
            SeismicEthApiError::EnclaveError("test".to_string()).into();
        assert_eq!(err.message(), "enclave error: test");
    }
}
