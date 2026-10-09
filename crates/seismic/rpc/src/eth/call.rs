use crate::{SeismicEthApi, SeismicEthApiError};
use reth_evm::{BlockEnvAccess, EvmEnvFor, SpecFor, TxEnvFor};
use reth_rpc_eth_api::{
    helpers::{estimate::EstimateCall, Call, EthCall},
    EthApiTypes, FromEthApiError, FromEvmError, RpcConvert, RpcNodeCore, RpcTxReq,
};
use reth_rpc_eth_types::EthApiError;
use revm::Database;
use seismic_revm::transaction::abstraction::SeismicTxTr;

impl<N, Rpc> EthCall for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    TxEnvFor<N::Evm>: SeismicTxTr,
    Rpc: RpcConvert<
        Primitives = N::Primitives,
        Error = SeismicEthApiError,
        TxEnv = TxEnvFor<N::Evm>,
        Spec = SpecFor<N::Evm>,
    >,
{
}

impl<N, Rpc> EstimateCall for SeismicEthApi<N, Rpc>
where
    Self: Call,
    Self::Error: From<EthApiError>,
    N: RpcNodeCore,
    Rpc: RpcConvert<
        Primitives = N::Primitives,
        Error = SeismicEthApiError,
        TxEnv = TxEnvFor<N::Evm>,
        Spec = SpecFor<N::Evm>,
    >,
{
}

impl<N, Rpc> Call for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    TxEnvFor<N::Evm>: SeismicTxTr,
    Rpc: RpcConvert<
        Primitives = N::Primitives,
        Error = SeismicEthApiError,
        TxEnv = TxEnvFor<N::Evm>,
        Spec = SpecFor<N::Evm>,
    >,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    /// Single-asset allowance from the requested simulation state (including permitted
    /// overrides), not the pool's approximate aggregate or a separate latest provider.
    /// The estimator's binary search and zero-price control flow remain unchanged.
    fn caller_gas_allowance(
        &self,
        mut db: impl Database<Error: Into<EthApiError>>,
        _evm_env: &EvmEnvFor<Self::Evm>,
        tx_env: &TxEnvFor<Self::Evm>,
    ) -> Result<u64, Self::Error> {
        super::payment::caller_gas_allowance(&mut db, tx_env, u64::MAX)
    }

    fn create_txn_env(
        &self,
        evm_env: &EvmEnvFor<Self::Evm>,
        mut request: RpcTxReq<Rpc::Network>,
        mut db: impl Database<Error: Into<EthApiError>>,
    ) -> Result<TxEnvFor<N::Evm>, Self::Error> {
        // Mutate only the inner account field. Pass the *whole* network request to the
        // converter so signed selectors and signed-read metadata are never discarded.
        if request.as_ref().nonce.is_none() {
            let caller = request.as_ref().from.unwrap_or_default();
            let nonce = db
                .basic(caller)
                .map_err(|error| Self::Error::from_eth_err(error.into()))?
                .map(|account| account.nonce)
                .unwrap_or_default();
            request.as_mut().nonce = Some(nonce);
        }
        self.tx_resp_builder().tx_env(request, &evm_env.cfg_env, evm_env.block_env.as_block_env())
    }
}
