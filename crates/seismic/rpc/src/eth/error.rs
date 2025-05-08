use reth_rpc_server_types::result::internal_rpc_err;
use reth_rpc_eth_types::error::api::FromEvmHalt;
use seismic_revm::{SeismicHaltReason};

#[derive(Debug, thiserror::Error)]

/// Seismic API error
pub enum SeismicApiError {
    /// Enclave error
    #[error("enclave error: {0}")]
    EnclaveError(String),
}

impl From<SeismicApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: SeismicApiError) -> Self {
        match error {
            SeismicApiError::EnclaveError(e) => internal_rpc_err(format!("enclave error: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::SeismicApiError;

    #[test]
    fn enclave_error_message() {
        let err: jsonrpsee::types::error::ErrorObject<'static> =
            SeismicApiError::EnclaveError("test".to_string()).into();
        assert_eq!(err.message(), "enclave error: test");
    }
}

use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicRawTxRequest};
