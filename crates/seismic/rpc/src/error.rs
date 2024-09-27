use jsonrpsee_types::error::{ErrorObject, INTERNAL_ERROR_CODE};
/// Seismic specific errors, that extend [`EthApiError`].
use reth::rpc::server_types::eth::EthApiError;
use reth_node_core::rpc::{eth::AsEthApiError, result::internal_rpc_err};
use reth_rpc_types::ToRpcError;

#[derive(Debug, thiserror::Error)]
pub enum SeismicApiError {
    /// L1 ethereum error.
    #[error(transparent)]
    Eth(#[from] EthApiError),
    /// Thrown when an error occurs in Seismic API.
    #[error("Seismic API error 1")]
    NonceCannotBeFound,
    /// Thrown when another error occurs in Seismic API.
    #[error("Seismic API error 2")]
    GasCannotBeEstimated,
    #[error("Seismic API error 3")]
    FailedToCommitPreimages,
    #[error("Seismic API error 4")]
    TransactionRequestCannotBeBuilt,
    #[error("Seismic API error 5")]
    FailedToSignTransaction,
    #[error("Seismic API error 6")]
    FailedToSubmitTransaction,
    #[error("Seismic API error 7")]
    FailedToGetGasPrice,
    #[error("Seismic API error 8")]
    FailedToDecodeTransaction,
}

impl AsEthApiError for SeismicApiError {
    fn as_err(&self) -> Option<&EthApiError> {
        match self {
            Self::Eth(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SeismicApiError> for jsonrpsee_types::error::ErrorObject<'static> {
    fn from(err: SeismicApiError) -> Self {
        match err {
            SeismicApiError::Eth(err) => err.into(),
            SeismicApiError::NonceCannotBeFound |
            SeismicApiError::GasCannotBeEstimated |
            SeismicApiError::FailedToCommitPreimages |
            SeismicApiError::TransactionRequestCannotBeBuilt |
            SeismicApiError::FailedToSignTransaction |
            SeismicApiError::FailedToSubmitTransaction |
            SeismicApiError::FailedToGetGasPrice |
            SeismicApiError::FailedToDecodeTransaction => internal_rpc_err(err.to_string()),
        }
    }
}

impl ToRpcError for SeismicApiError {
    fn to_rpc_error(&self) -> jsonrpsee_types::error::ErrorObject<'static> {
        ErrorObject::owned(INTERNAL_ERROR_CODE, self.to_string(), None::<String>)
    }
}

impl From<SeismicApiError> for EthApiError {
    fn from(error: SeismicApiError) -> Self {
        match error {
            SeismicApiError::Eth(err) => err,
            err => Self::Other(Box::new(err)),
        }
    }
}
