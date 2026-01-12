//! Seismic-Reth `eth_` endpoint implementation.

pub mod api;
pub mod ext;
pub mod receipt;
pub mod transaction;
pub mod utils;

pub use receipt::SeismicReceiptConverter;

mod block;
mod call;
mod pending_block;

use crate::{
    eth::transaction::{SeismicRpcTxConverter, SeismicSimTxConverter},
    SeismicEthApiError,
};
use alloy_consensus::TxEip4844;
use alloy_primitives::U256;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeComponents, HeaderTy};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_rpc::{
    eth::{core::EthApiInner, DevSigner},
    RpcTypes,
};
use reth_rpc_eth_api::{
    helpers::{
        pending_block::BuildPendingEnv, spec::SignersForApi, AddDevSigners, EthApiSpec, EthFees,
        EthState, LoadFee, LoadPendingBlock, LoadState, SpawnBlocking, Trace,
    },
    EthApiTypes, FromEvmError, FullEthApiServer, RpcConvert, RpcConverter, RpcNodeCore,
    RpcNodeCoreExt, SignableTxRequest,
};
use reth_rpc_eth_types::{EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth_storage_api::{BlockReader, ProviderHeader, ProviderTx};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskSpawner,
};
use seismic_alloy_network::SeismicReth;
use std::{fmt, marker::PhantomData, sync::Arc};

use reth_rpc_convert::transaction::{EthTxEnvError, TryIntoTxEnv};
use revm_context::{BlockEnv, CfgEnv, TxEnv};
use seismic_alloy_rpc_types::SeismicTransactionRequest;

// Additional imports for SignableTxRequest wrapper
use alloy_primitives::Signature;
use reth_rpc_convert::SignTxRequestError;
use seismic_alloy_network::TxSigner;

/// Newtype wrapper around `SeismicTransactionRequest` to implement `SignableTxRequest`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignableSeismicTransactionRequest(pub SeismicTransactionRequest);

impl From<SeismicTransactionRequest> for SignableSeismicTransactionRequest {
    fn from(req: SeismicTransactionRequest) -> Self {
        Self(req)
    }
}

impl From<alloy_rpc_types_eth::TransactionRequest> for SignableSeismicTransactionRequest {
    fn from(req: alloy_rpc_types_eth::TransactionRequest) -> Self {
        Self(SeismicTransactionRequest { inner: req, seismic_elements: None })
    }
}

impl AsRef<alloy_rpc_types_eth::TransactionRequest> for SignableSeismicTransactionRequest {
    fn as_ref(&self) -> &alloy_rpc_types_eth::TransactionRequest {
        &self.0.inner
    }
}

impl AsMut<alloy_rpc_types_eth::TransactionRequest> for SignableSeismicTransactionRequest {
    fn as_mut(&mut self) -> &mut alloy_rpc_types_eth::TransactionRequest {
        &mut self.0.inner
    }
}

impl TryIntoTxEnv<seismic_revm::SeismicTransaction<TxEnv>> for SignableSeismicTransactionRequest {
    type Err = EthTxEnvError;

    fn try_into_tx_env<Spec>(
        self,
        cfg_env: &CfgEnv<Spec>,
        block_env: &BlockEnv,
    ) -> Result<seismic_revm::SeismicTransaction<TxEnv>, Self::Err> {
        // First convert the inner transaction to TxEnv
        let base_tx_env = self.0.inner.try_into_tx_env(cfg_env, block_env)?;
        // Then wrap it in SeismicTransaction
        Ok(seismic_revm::SeismicTransaction::new(base_tx_env))
    }
}

impl SignableTxRequest<reth_seismic_primitives::SeismicTransactionSigned>
    for SignableSeismicTransactionRequest
{
    async fn try_build_and_sign(
        self,
        _signer: impl TxSigner<Signature> + Send,
    ) -> Result<reth_seismic_primitives::SeismicTransactionSigned, SignTxRequestError> {
        // TODO: Implement proper signing logic
        // For now, create a placeholder transaction to make it compile
        use alloy_consensus::{Signed, TxLegacy};
        use alloy_primitives::{B256, U256};
        use reth_seismic_primitives::SeismicTransactionSigned;
        use seismic_alloy_consensus::SeismicTxEnvelope;

        // Create a minimal transaction for compilation - this should be replaced with proper
        // signing
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 20_000_000_000u128,
            gas_limit: 21_000,
            to: alloy_primitives::TxKind::Create,
            value: U256::ZERO,
            input: Default::default(),
        };

        let signature = Signature::new(U256::ZERO, U256::ZERO, false);
        let signed_tx = Signed::new_unchecked(tx, signature, B256::ZERO);
        let envelope = SeismicTxEnvelope::<TxEip4844>::Legacy(signed_tx);
        let seismic_signed = SeismicTransactionSigned::from(envelope);

        Ok(seismic_signed)
    }
}

/// Wrapper network type that uses `SignableSeismicTransactionRequest`
#[derive(Debug, Clone)]
pub struct SeismicRethWithSignable;

impl reth_rpc_eth_api::RpcTypes for SeismicRethWithSignable {
    type TransactionRequest = SignableSeismicTransactionRequest;
    type Receipt = <SeismicReth as reth_rpc_eth_api::RpcTypes>::Receipt;
    type TransactionResponse = <SeismicReth as reth_rpc_eth_api::RpcTypes>::TransactionResponse;
    type Header = <SeismicReth as reth_rpc_eth_api::RpcTypes>::Header;
}

/// Adapter for [`EthApiInner`], which holds all the data required to serve core `eth_` API.
pub type EthApiNodeBackend<N, Rpc> = EthApiInner<N, Rpc>;

/// A helper trait with requirements for [`RpcNodeCore`] to be used in [`SeismicEthApi`].
pub trait SeismicNodeCore: RpcNodeCore<Provider: BlockReader> {}
impl<T> SeismicNodeCore for T where T: RpcNodeCore<Provider: BlockReader> {}

/// seismic-reth `Eth` API implementation.
#[derive(Clone)]
pub struct SeismicEthApi<N: SeismicNodeCore, Rpc: RpcConvert> {
    /// Inner `Eth` API implementation.
    pub inner: Arc<EthApiInner<N, Rpc>>,
}

impl<N: RpcNodeCore, Rpc: RpcConvert> SeismicEthApi<N, Rpc> {
    /// Returns a reference to the [`EthApiNodeBackend`].
    pub fn eth_api(&self) -> &EthApiNodeBackend<N, Rpc> {
        &self.inner
    }

    /// Build a [`SeismicEthApi`] using [`SeismicEthApiBuilder`].
    pub const fn builder() -> SeismicEthApiBuilder<Rpc> {
        SeismicEthApiBuilder::new()
    }
}

impl<N, Rpc> EthApiTypes for SeismicEthApi<N, Rpc>
where
    // Self: Send + Sync,
    // N: SeismicNodeCore,
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    type Error = SeismicEthApiError;
    type NetworkTypes = Rpc::Network;
    type RpcConvert = Rpc;

    fn tx_resp_builder(&self) -> &Self::RpcConvert {
        self.inner.tx_resp_builder()
    }
}

impl<N, Rpc> RpcNodeCore for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    type Primitives = N::Primitives;
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Evm = N::Evm;
    type Network = N::Network;

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.inner.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.inner.network()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.inner.provider()
    }
}

impl<N, Rpc> RpcNodeCoreExt for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    #[inline]
    fn cache(&self) -> &EthStateCache<N::Primitives> {
        self.inner.cache()
    }
}

impl<N, Rpc> EthApiSpec for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    type Transaction = ProviderTx<Self::Provider>;
    type Rpc = Rpc::Network;

    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
    }

    #[inline]
    fn signers(&self) -> &SignersForApi<Self> {
        self.inner.signers()
    }
}

impl<N, Rpc> SpawnBlocking for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    #[inline]
    fn io_task_spawner(&self) -> impl TaskSpawner {
        self.inner.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.inner.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.inner.blocking_task_guard()
    }
}

impl<N, Rpc> LoadFee for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.inner.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache<ProviderHeader<N::Provider>> {
        self.inner.fee_history_cache()
    }
}

impl<N, Rpc> LoadState for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
    Self: LoadPendingBlock,
{
}

impl<N, Rpc> EthState for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
    Self: LoadPendingBlock,
{
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }

    #[inline]
    fn storage_apis_enabled(&self) -> bool {
        self.inner.storage_apis_enabled()
    }
}

impl<N, Rpc> EthFees for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
}

impl<N, Rpc> Trace for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
}

impl<N, Rpc> AddDevSigners for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<
        Network: RpcTypes<TransactionRequest: SignableTxRequest<ProviderTx<N::Provider>>>,
    >,
{
    fn with_dev_accounts(&self) {
        *self.inner.signers().write() = DevSigner::random_signers(20)
    }
}

impl<N: SeismicNodeCore, Rpc: RpcConvert> fmt::Debug for SeismicEthApi<N, Rpc> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeismicEthApi").finish_non_exhaustive()
    }
}

/// Converter for Seismic RPC types.
pub type SeismicRpcConvert<N, NetworkT> = RpcConverter<
    NetworkT,
    <N as FullNodeComponents>::Evm,
    SeismicReceiptConverter,
    (),
    (),
    crate::eth::transaction::SeismicSimTxConverter,
    crate::eth::transaction::SeismicRpcTxConverter,
>;

/// Builds [`SeismicEthApi`] for Optimism.
#[derive(Debug)]
pub struct SeismicEthApiBuilder<NetworkT> {
    _nt: PhantomData<NetworkT>,
}

impl<NetworkT> Default for SeismicEthApiBuilder<NetworkT> {
    fn default() -> Self {
        Self { _nt: PhantomData }
    }
}

impl<NetworkT> SeismicEthApiBuilder<NetworkT> {
    /// Creates a [`SeismicEthApiBuilder`] instance from core components.
    pub const fn new() -> Self {
        Self { _nt: PhantomData }
    }
}

impl<N, NetworkT> EthApiBuilder<N> for SeismicEthApiBuilder<NetworkT>
where
    N: FullNodeComponents<
        Evm: ConfigureEvm<
            NextBlockEnvCtx: BuildPendingEnv<HeaderTy<N::Types>>
                                 // + From<ExecutionPayloadBaseV1>
                                 + Unpin,
        >,
    >,
    NetworkT: RpcTypes,
    SeismicRpcConvert<N, NetworkT>: RpcConvert<Network = NetworkT>,
    SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>:
        FullEthApiServer<Provider = N::Provider, Pool = N::Pool> + AddDevSigners,
{
    type EthApi = SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let receipt_converter = SeismicReceiptConverter::new();

        let rpc_converter: SeismicRpcConvert<N, NetworkT> = RpcConverter::new(receipt_converter)
            .with_sim_tx_converter(SeismicSimTxConverter::new())
            .with_rpc_tx_converter(SeismicRpcTxConverter::new());

        let eth_api = ctx.eth_api_builder().with_rpc_converter(rpc_converter).build_inner();

        Ok(SeismicEthApi { inner: Arc::new(eth_api) })
    }
}
