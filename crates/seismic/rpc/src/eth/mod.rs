//! Seismic-Reth `eth_` endpoint implementation.

pub mod api;
pub mod ext;
pub mod receipt;
pub mod transaction;
pub mod utils;

mod block;
mod call;
mod pending_block;

use alloy_primitives::U256;
use reth_chain_state::CanonStateSubscriptions;
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_network_api::NetworkInfo;
use reth_node_api::{FullNodeComponents, FullNodeTypes, HeaderTy, NodePrimitives};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_rpc::{eth::{core::EthApiInner, DevSigner}, RpcTypes};
use reth_rpc_eth_api::{
    helpers::{
        pending_block::BuildPendingEnv, spec::SignersForApi, AddDevSigners, EthApiSpec, EthFees, EthSigner, EthState, LoadBlock, LoadFee, LoadPendingBlock, LoadState, SpawnBlocking, Trace
    }, EthApiTypes, FromEvmError, FullEthApiServer, RpcConvert, RpcConverter, RpcNodeCore, RpcNodeCoreExt, SignableTxRequest
};
use reth_rpc_eth_types::{EthApiError, EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth_seismic_primitives::SeismicPrimitives;
use reth_storage_api::{
    BlockNumReader, BlockReader, BlockReaderIdExt, ProviderBlock, ProviderHeader, ProviderReceipt,
    ProviderTx, StageCheckpointReader, StateProviderFactory,
};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskSpawner,
};
use reth_transaction_pool::TransactionPool;
use seismic_alloy_network::SeismicReth;
use std::{fmt, marker::PhantomData, sync::Arc};

use crate::SeismicEthApiError;

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

impl<N: RpcNodeCore, Rpc: RpcConvert> SeismicEthApi<N, Rpc>
{
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
    N: SeismicNodeCore,
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

impl<N, Rpc> LoadState for SeismicEthApi<N, Rpc> where
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
    Rpc: RpcConvert<Primitives = N::Primitives, Network = SeismicReth>,
{
}

impl<N, Rpc> AddDevSigners for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<
        Network: RpcTypes<TransactionRequest: SignableTxRequest<ProviderTx<N::Provider>>>,
    >
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

/// Converter for OP RPC types.
pub type SeismicRpcConvert<N, NetworkT> = RpcConverter<
    NetworkT,
    <N as FullNodeComponents>::Evm,
    (),
    (),
    (),
>;


/// Builds [`SeismicEthApi`] for Optimism.
#[derive(Debug)]
pub struct SeismicEthApiBuilder<NetworkT> {
    _nt: PhantomData<NetworkT>
}

impl<NetworkT> Default for SeismicEthApiBuilder<NetworkT> {
    fn default() -> Self {
        SeismicEthApiBuilder { _nt: PhantomData }
    }
}

impl<NetworkT> SeismicEthApiBuilder<NetworkT> {
    /// Creates a [`SeismicEthApiBuilder`] instance from core components.
    pub const fn new() -> Self {
        SeismicEthApiBuilder { _nt: PhantomData }
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
    SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>: FullEthApiServer<
        Provider = N::Provider,
        Pool = N::Pool
    > + AddDevSigners,
{
    type EthApi = SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let eth_api = reth_rpc::EthApiBuilder::new(
            ctx.components.provider().clone(),
            ctx.components.pool().clone(),
            ctx.components.network().clone(),
            ctx.components.evm_config().clone(),
        )
        .eth_cache(ctx.cache)
        .task_spawner(ctx.components.task_executor().clone())
        .gas_cap(ctx.config.rpc_gas_cap.into())
        .max_simulate_blocks(ctx.config.rpc_max_simulate_blocks)
        .eth_proof_window(ctx.config.eth_proof_window)
        .fee_history_cache_config(ctx.config.fee_history_cache)
        .proof_permits(ctx.config.proof_permits)
        .build_inner();

        Ok(SeismicEthApi { inner: Arc::new(eth_api) })
    }
}
