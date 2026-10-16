//! Typed pool payment and maintenance errors with privacy-safe diagnostics.

use reth_provider::ProviderError;
use reth_transaction_pool::error::PoolTransactionError;
use revm::context::result::InvalidTransaction;
use seismic_revm::gas_token_registry::RegistryError;
use std::{any::Any, fmt};

/// Maintenance refresh failure. Neither variant authorizes a fabricated balance
/// or rejects a particular pooled transaction; failed refreshes remain dirty.
#[derive(Debug)]
pub enum SeismicBalanceError {
    /// A required registry, token, or account read failed.
    Provider(ProviderError),
    /// Registry state could not be decoded, with privacy-safe diagnostics.
    Registry(SeismicPaymentError),
}

impl From<RegistryError<ProviderError>> for SeismicBalanceError {
    fn from(error: RegistryError<ProviderError>) -> Self {
        match error {
            RegistryError::Storage(error) => Self::Provider(error),
            RegistryError::Transaction(error) => Self::Registry(SeismicPaymentError(error)),
        }
    }
}

impl fmt::Display for SeismicBalanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "gas balance refresh provider error: {error}"),
            Self::Registry(error) => write!(f, "gas balance refresh registry error: {error}"),
        }
    }
}

impl std::error::Error for SeismicBalanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::Registry(error) => Some(error),
        }
    }
}

/// Deterministic payment invalidity, kept distinct from provider failures.
///
/// The structured reason is available to trusted in-process consumers, but neither
/// `Display`, `Debug`, nor the error source chain exposes private balance amounts.
#[derive(Clone, PartialEq, Eq)]
pub struct SeismicPaymentError(pub(crate) InvalidTransaction);

impl SeismicPaymentError {
    /// Inspect the original typed invalidity internally. Do not serialize or log
    /// this value directly: some variants contain private balance amounts.
    pub const fn reason(&self) -> &InvalidTransaction {
        &self.0
    }
}

impl fmt::Display for SeismicPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason() {
            InvalidTransaction::LackOfFundForMaxFee { .. } => {
                f.write_str("sender does not have enough funds for the selected gas payment")
            }
            InvalidTransaction::InvalidGasPaymentSelector => {
                f.write_str("invalid gas payment selector")
            }
            InvalidTransaction::GasTokenRegistryTooLarge => {
                f.write_str("gas token registry exceeds capacity")
            }
            InvalidTransaction::GasTokenNotRegistered(token) => {
                write!(f, "gas token {token} is not registered")
            }
            InvalidTransaction::GasTokenInactive(token) => {
                write!(f, "gas token {token} is inactive")
            }
            InvalidTransaction::UnsupportedGasTokenMode { token, .. } => {
                write!(f, "gas token {token} has an unsupported storage mode")
            }
            InvalidTransaction::UnsupportedGasTokenDecimals { token, .. } => {
                write!(f, "gas token {token} has unsupported decimals")
            }
            InvalidTransaction::GasTokenBalanceModeMismatch { token, .. } => {
                write!(f, "gas token {token} balance storage mode is incompatible")
            }
            InvalidTransaction::OverflowPaymentInTransaction => {
                f.write_str("transaction payment overflows")
            }
            // Do not delegate new/unknown variants to revm's potentially unredacted formatter.
            _ => f.write_str("invalid gas payment"),
        }
    }
}

impl fmt::Debug for SeismicPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SeismicPaymentError({self})")
    }
}

impl std::error::Error for SeismicPaymentError {}

impl PoolTransactionError for SeismicPaymentError {
    fn is_bad_transaction(&self) -> bool {
        // Registry configuration and balances depend on mutable canonical state;
        // peers must not be penalized merely for seeing a different head.
        matches!(
            self.reason(),
            InvalidTransaction::InvalidGasPaymentSelector |
                InvalidTransaction::OverflowPaymentInTransaction
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_transaction_pool::error::InvalidPoolTransactionError;

    #[test]
    fn payment_diagnostics_redact_private_amounts() {
        let reason = InvalidTransaction::LackOfFundForMaxFee {
            fee: Box::new(U256::from(987_654_321)),
            balance: Box::new(U256::from(123_456_789)),
        };
        let error = SeismicPaymentError(reason.clone());
        assert_eq!(error.reason(), &reason);
        assert!(!error.is_bad_transaction());
        assert!(std::error::Error::source(&error).is_none());
        let pool_error = InvalidPoolTransactionError::other(error);
        for diagnostic in [pool_error.to_string(), format!("{pool_error:?}")] {
            assert!(!diagnostic.contains("987654321"));
            assert!(!diagnostic.contains("123456789"));
        }
        assert_eq!(
            pool_error.downcast_other_ref::<SeismicPaymentError>().map(SeismicPaymentError::reason),
            Some(&reason)
        );
    }

    #[test]
    fn registry_state_errors_do_not_penalize_peers() {
        let token = Address::with_last_byte(0x43);
        for reason in [
            InvalidTransaction::GasTokenRegistryTooLarge,
            InvalidTransaction::GasTokenNotRegistered(token),
            InvalidTransaction::GasTokenInactive(token),
            InvalidTransaction::UnsupportedGasTokenMode { token, mode: 2 },
            InvalidTransaction::UnsupportedGasTokenDecimals { token, decimals: 19 },
            InvalidTransaction::GasTokenBalanceModeMismatch { token, account: Address::ZERO },
        ] {
            assert!(!SeismicPaymentError(reason).is_bad_transaction());
        }
        assert!(
            SeismicPaymentError(InvalidTransaction::InvalidGasPaymentSelector).is_bad_transaction()
        );
        assert!(SeismicPaymentError(InvalidTransaction::OverflowPaymentInTransaction)
            .is_bad_transaction());
    }
}
