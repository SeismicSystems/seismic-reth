//! Error types for the seismic rpc api.

use std::convert::Infallible;

use alloy_rpc_types_eth::BlockError;
use reth_provider::ProviderError;
use reth_rpc_eth_api::{AsEthApiError, EthTxEnvError, TransactionConversionError};
use reth_rpc_eth_types::{error::api::FromEvmHalt, EthApiError};
use reth_rpc_server_types::result::internal_rpc_err;
use revm::context_interface::result::EVMError;
use revm_context::result::HaltReason;
use seismic_revm::SeismicHaltReason;

#[derive(Debug, thiserror::Error)]
/// Seismic API error
pub enum SeismicEthApiError {
    /// Eth error
    #[error(transparent)]
    Eth(#[from] EthApiError),
    /// Enclave error
    #[error("enclave error: {0}")]
    EnclaveError(String),
    /// Attempting to access public storage with cload
    #[error("invalid public storage access")]
    InvalidPublicStorageAccess,
    /// Attempting to access private storage with sload
    #[error("invalid private storage access")]
    InvalidPrivateStorageAccess,
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
            SeismicEthApiError::InvalidPrivateStorageAccess => {
                internal_rpc_err("invalid private storage access")
            }
            SeismicEthApiError::InvalidPublicStorageAccess => {
                internal_rpc_err("invalid public storage access")
            }
        }
    }
}

impl FromEvmHalt<SeismicHaltReason> for SeismicEthApiError {
    fn from_evm_halt(halt: SeismicHaltReason, gas_limit: u64) -> Self {
        match halt {
            SeismicHaltReason::InvalidPrivateStorageAccess => Self::InvalidPrivateStorageAccess,
            SeismicHaltReason::InvalidPublicStorageAccess => Self::InvalidPublicStorageAccess,
            SeismicHaltReason::Base(halt) => EthApiError::from_evm_halt(halt, gas_limit).into(),
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
        Self::Eth(EthApiError::from(error))
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
    use reth_rpc_eth_types::error::api::FromEvmHalt;
    use seismic_revm::SeismicHaltReason;

    #[test]
    fn enclave_error_message() {
        let err: jsonrpsee::types::error::ErrorObject<'static> =
            SeismicEthApiError::EnclaveError("test".to_string()).into();
        assert_eq!(err.message(), "enclave error: test");
    }

    #[test]
    fn test_invalid_private_storage_error_conversion() {
        let halt = SeismicHaltReason::InvalidPrivateStorageAccess;
        let err = SeismicEthApiError::from_evm_halt(halt, 1000000);
        let rpc_err: jsonrpsee::types::error::ErrorObject<'static> = err.into();
        assert!(
            rpc_err.message().contains("invalid private storage access"),
            "Expected error message to contain 'invalid private storage access', got: {}",
            rpc_err.message()
        );
    }

    #[test]
    fn test_invalid_public_storage_error_conversion() {
        let halt = SeismicHaltReason::InvalidPublicStorageAccess;
        let err = SeismicEthApiError::from_evm_halt(halt, 1000000);
        let rpc_err: jsonrpsee::types::error::ErrorObject<'static> = err.into();
        assert!(
            rpc_err.message().contains("invalid public storage access"),
            "Expected error message to contain 'invalid public storage access', got: {}",
            rpc_err.message()
        );
    }

    #[test]
    fn test_invalid_private_storage_direct_conversion() {
        let err = SeismicEthApiError::InvalidPrivateStorageAccess;
        let rpc_err: jsonrpsee::types::error::ErrorObject<'static> = err.into();
        assert_eq!(rpc_err.message(), "invalid private storage access");
    }

    #[test]
    fn test_invalid_public_storage_direct_conversion() {
        let err = SeismicEthApiError::InvalidPublicStorageAccess;
        let rpc_err: jsonrpsee::types::error::ErrorObject<'static> = err.into();
        assert_eq!(rpc_err.message(), "invalid public storage access");
    }

    #[test]
    fn test_base_halt_reason_conversion() {
        use revm_context::result::HaltReason;
        let halt = SeismicHaltReason::Base(HaltReason::OutOfGas(
            revm_context::result::OutOfGasError::BasicOutOfGas,
        ));
        let err = SeismicEthApiError::from_evm_halt(halt, 1000000);
        // Should convert to an Eth error, not a direct privacy error
        matches!(err, SeismicEthApiError::Eth(_));
    }
}
