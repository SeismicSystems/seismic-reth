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
    /// Attempting to transfer value > 0
    #[cfg(feature = "no-value-transfers")]
    #[error("attempting to transfer value > 0")]
    AttemptingToTransferValue,
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
            SeismicHaltReason::InvalidPrivateStorageAccess => {
                SeismicEthApiError::InvalidPrivateStorageAccess
            }
            SeismicHaltReason::InvalidPublicStorageAccess => {
                SeismicEthApiError::InvalidPublicStorageAccess
            }
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

    #[test]
    fn enclave_error_message() {
        let err: jsonrpsee::types::error::ErrorObject<'static> =
            SeismicEthApiError::EnclaveError("test".to_string()).into();
        assert_eq!(err.message(), "enclave error: test");
    }
}
