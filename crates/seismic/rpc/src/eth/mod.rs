//! OP-Reth `eth_` endpoint implementation.

// pub mod ext;
pub mod receipt;
pub mod transaction;

mod block;
// mod call;
// mod pending_block;

use alloy_primitives::U256;
use reth_chain_state::CanonStateSubscriptions;
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_network_api::NetworkInfo;
use reth_node_api::{FullNodeComponents, NodePrimitives, NodeTypesWithEngine};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_node_ethereum::EthereumEthApiBuilder;
use reth_rpc::{
    eth::{core::EthApiInner, DevSigner},
    EthApi,
};
use reth_rpc_eth_api::{
    helpers::{
        AddDevSigners, EthApiSpec, EthFees, EthSigner, EthState, LoadBlock, LoadFee, LoadState,
        SpawnBlocking, Trace,
    },
    EthApiTypes, FromEvmError, FullEthApiServer, RpcNodeCore, RpcNodeCoreExt,
};
use reth_rpc_eth_types::{EthApiError, EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth_seismic_evm::SeismicEvmConfig;
use reth_seismic_primitives::SeismicPrimitives;
use reth_seismic_txpool::SeismicTransactionPool;
use reth_storage_api::{
    BlockNumReader, BlockReader, BlockReaderIdExt, ProviderBlock, ProviderHeader, ProviderReceipt,
    ProviderTx, StageCheckpointReader, StateProviderFactory,
};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskSpawner,
};
use reth_transaction_pool::TransactionPool;
use seismic_alloy_network::Seismic;
use std::{fmt, ops::Deref, sync::Arc};

/// A helper trait with requirements for [`RpcNodeCore`] to be used in [`SeismicEthApi`].
pub trait SeismicNodeCore: RpcNodeCore<Provider: BlockReader> {}
impl<T> SeismicNodeCore for T where T: RpcNodeCore<Provider: BlockReader> {}

/// seismic-reth `Eth` API implementation.
#[derive(Clone)]
pub struct SeismicEthApi<N: SeismicNodeCore>(pub EthApi<N::Provider, N::Pool, N::Network, N::Evm>);

impl<N> EthApiTypes for SeismicEthApi<N>
where
    Self: Send + Sync,
    N: SeismicNodeCore,
{
    type Error = EthApiError;
    type NetworkTypes = Seismic;
    type TransactionCompat = Self;

    fn tx_resp_builder(&self) -> &Self::TransactionCompat {
        self
    }
}

impl<N> Deref for SeismicEthApi<N>
where
    N: SeismicNodeCore,
{
    type Target = EthApi<N::Provider, N::Pool, N::Network, N::Evm>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N> RpcNodeCore for SeismicEthApi<N>
where
    N: SeismicNodeCore,
{
    type Primitives = SeismicPrimitives;
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Evm = <N as RpcNodeCore>::Evm;
    type Network = <N as RpcNodeCore>::Network;
    type PayloadBuilder = ();

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.0.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.0.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.0.network()
    }

    #[inline]
    fn payload_builder(&self) -> &Self::PayloadBuilder {
        &()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.0.provider()
    }
}

impl<N> RpcNodeCoreExt for SeismicEthApi<N>
where
    N: SeismicNodeCore,
{
    #[inline]
    fn cache(&self) -> &EthStateCache<ProviderBlock<N::Provider>, ProviderReceipt<N::Provider>> {
        self.0.cache()
    }
}

impl<N> EthApiSpec for SeismicEthApi<N>
where
    N: SeismicNodeCore<
        Provider: ChainSpecProvider<ChainSpec: EthereumHardforks>
                      + BlockNumReader
                      + StageCheckpointReader,
        Network: NetworkInfo,
    >,
{
    type Transaction = ProviderTx<Self::Provider>;

    #[inline]
    fn starting_block(&self) -> U256 {
        self.0.starting_block()
    }

    #[inline]
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.0.signers()
    }
}

impl<N> SpawnBlocking for SeismicEthApi<N>
where
    Self: Send + Sync + Clone + 'static,
    N: RpcNodeCore<Provider: BlockReader>,
{
    #[inline]
    fn io_task_spawner(&self) -> impl TaskSpawner {
        self.0.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.0.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.0.blocking_task_guard()
    }
}

impl<N> LoadFee for SeismicEthApi<N>
where
    Self: LoadBlock<Provider = N::Provider>,
    N: SeismicNodeCore<
        Provider: BlockReaderIdExt
                      + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
    >,
{
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.0.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache {
        self.0.fee_history_cache()
    }
}

impl<N> LoadState for SeismicEthApi<N> where
    N: SeismicNodeCore<
        Provider: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks>,
        Pool: TransactionPool,
    >
{
}

impl<N> EthState for SeismicEthApi<N>
where
    Self: LoadState + SpawnBlocking,
    N: SeismicNodeCore,
    EthApi<N::Provider, N::Pool, N::Network, N::Evm>: EthState,
{
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.0.max_proof_window()
    }
}

impl<N> EthFees for SeismicEthApi<N>
where
    Self: LoadFee,
    N: SeismicNodeCore,
{
}

impl<N> Trace for SeismicEthApi<N>
where
    Self: RpcNodeCore<Provider: BlockReader>
        + LoadState<
            Evm: ConfigureEvm<
                Primitives: NodePrimitives<
                    BlockHeader = ProviderHeader<Self::Provider>,
                    SignedTx = ProviderTx<Self::Provider>,
                >,
            >,
            Error: FromEvmError<Self::Evm>,
        >,
    N: SeismicNodeCore,
{
}

impl<N> AddDevSigners for SeismicEthApi<N>
where
    N: SeismicNodeCore,
{
    fn with_dev_accounts(&self) {
        self.0.with_dev_accounts()
    }
}

impl<N: SeismicNodeCore> fmt::Debug for SeismicEthApi<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeismicEthApi").finish_non_exhaustive()
    }
}

/// Builds [`EthApi`](reth_rpc::EthApi) for Seismic.
#[derive(Debug, Default)]
pub struct SeismicEthApiBuilder;

impl<N> EthApiBuilder<N> for SeismicEthApiBuilder
where
    N: FullNodeComponents,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type EthApi = SeismicEthApi<N>;

    fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> Self::EthApi {
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
        .build();

        SeismicEthApi(eth_api)
    }
}
