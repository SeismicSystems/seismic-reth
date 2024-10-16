use futures::Future;
use reth_primitives::Bytes;
use reth_rpc_eth_api::{helpers::{Call, LoadPendingBlock}, FromEthApiError};
use reth_rpc_eth_types::{error::ensure_success, utils::recover_raw_transaction};
use reth_rpc_types::{state::EvmOverrides, BlockId};
use reth_rpc_types_compat::transaction::transaction_to_call_request;

/// Seismic call related functions
pub trait SeismicCall: Call + LoadPendingBlock {
    /// Executes the call request (`eth_call`) and returns the output
    fn call(
        &self,
        request: Bytes,
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + Send {
        async move {
            // `call` must be accompanied with a valid signature.
            let recovered = recover_raw_transaction(request.clone())?;
            let transaction_request = transaction_to_call_request(recovered.into_ecrecovered_transaction());

            let (res, _env) =
                self.transact_call_at(transaction_request, BlockId::latest(), EvmOverrides::default()).await?;

            ensure_success(res.result).map_err(Self::Error::from_eth_err)
        }
    }
}