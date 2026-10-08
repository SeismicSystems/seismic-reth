//! Exercise the EVM → block → payload error channel used by production selection.
use super::*;
use alloy_primitives::{Address, B256};
use revm::context::result::{EVMError, InvalidTransaction};
use std::io;

fn block_error(error: InvalidTransaction) -> BlockExecutionError {
    BlockExecutionError::evm(EVMError::<io::Error>::Transaction(error), B256::ZERO)
}

#[test]
fn deterministic_payment_errors_skip_dependent_nonces() {
    let token = Address::with_last_byte(0x44);
    for error in [
        InvalidTransaction::InvalidGasPaymentSelector,
        InvalidTransaction::GasTokenRegistryTooLarge,
        InvalidTransaction::GasTokenNotRegistered(token),
        InvalidTransaction::GasTokenInactive(token),
        InvalidTransaction::UnsupportedGasTokenMode { token, mode: 2 },
        InvalidTransaction::UnsupportedGasTokenDecimals { token, decimals: 19 },
        InvalidTransaction::GasTokenBalanceModeMismatch {
            token,
            account: Address::with_last_byte(0x42),
        },
    ] {
        assert!(matches!(invalidates_dependents(block_error(error)), Ok(true)));
    }
}

#[test]
fn low_nonce_skips_only_that_transaction() {
    assert!(matches!(
        invalidates_dependents(block_error(InvalidTransaction::NonceTooLow { tx: 0, state: 1 })),
        Ok(false)
    ));
}

#[test]
fn database_and_internal_errors_abort_payload_building() {
    let database_error = BlockExecutionError::evm(
        EVMError::<io::Error>::Database(io::Error::other("required registry read failed")),
        B256::ZERO,
    );
    assert!(database_error.as_validation().is_none());
    assert!(invalidates_dependents(database_error).is_err());
    assert!(invalidates_dependents(BlockExecutionError::msg("internal failure")).is_err());
}
