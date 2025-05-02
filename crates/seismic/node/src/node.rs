//! Seismic Node types config.

use crate::{
    args::EnclaveArgs,
    engine::{SeismicEngineTypes, SeismicEngineValidator},
    txpool::SeismicTransactionPool,
};
use alloy_consensus::transaction::PooledTransaction;
use alloy_eips::merge::EPOCH_SLOTS;
use alloy_rpc_types_engine::PayloadAttributes;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_consensus::{ConsensusError, FullConsensus};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{
    execute::BasicBlockExecutorProvider, ConfigureEvm, EvmFactory, EvmFactoryFor,
    NextBlockEnvAttributes,
};
use reth_network::{NetworkConfig, NetworkHandle, NetworkManager, NetworkPrimitives, PeersInfo};
use reth_node_api::{
    AddOnsContext, FullNodeComponents, KeyHasherTy, NodeAddOns, NodePrimitives, PayloadTypes,
    PrimitivesTy, TxTy,
};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NetworkBuilder, PayloadBuilderBuilder, PoolBuilder, PoolBuilderConfigOverrides,
    },
    node::{FullNodeTypes, NodeTypes, NodeTypesWithEngine},
    rpc::{
        EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, RethRpcAddOns, RpcAddOns,
        RpcHandle,
    },
    BuilderContext, DebugNode, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig,
};
use reth_node_ethereum::{consensus::EthBeaconConsensus, EthereumEngineValidator};
use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_provider::{providers::ProviderFactoryBuilder, CanonStateSubscriptions, EthStorage};
use reth_rpc::{eth::core::EthApiFor, ValidationApi};
use reth_rpc_api::{BlockSubmissionValidationApiServer, DebugApiServer};
use reth_rpc_eth_api::{ext::L2EthApiExtServer, FullEthApiServer};
use reth_rpc_eth_types::{error::FromEvmError, EthApiError};
use reth_rpc_server_types::RethRpcModule;
use reth_seismic_evm::SeismicEvmConfig;
use reth_seismic_primitives::{SeismicPrimitives, SeismicReceipt, SeismicTransactionSigned};
use reth_seismic_rpc::{SeismicEthApi, SeismicEthApiBuilder};
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::{DiskFileBlobStore, DiskFileBlobStoreConfig},
    CoinbaseTipOrdering, EthPoolTransaction, EthPooledTransaction, EthTransactionPool,
    PoolTransaction, TransactionPool, TransactionValidationTaskExecutor,
};
use reth_trie_db::MerklePatriciaTrie;
use revm::context::TxEnv;
use seismic_alloy_consensus::SeismicTxEnvelope;
use std::{sync::Arc, time::SystemTime};
use reth_rpc_builder::config::RethRpcServerConfig;

/// Storage implementation for Optimism.
pub type SeismicStorage = EthStorage<SeismicTransactionSigned>;

/// Type configuration for a regular Seismic node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicNode;

impl SeismicNode {
    /// Returns the components for the given [`EnclaveArgs`].
    pub fn components<Node>(
        &self,
    ) -> ComponentsBuilder<
        Node,
        SeismicPoolBuilder,
        BasicPayloadServiceBuilder<SeismicPayloadBuilder>,
        SeismicNetworkBuilder,
        SeismicExecutorBuilder,
        SeismicConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<
                Payload = SeismicEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SeismicPrimitives,
            >,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(SeismicPoolBuilder::default())
            .payload(BasicPayloadServiceBuilder::<SeismicPayloadBuilder>::default())
            .network(SeismicNetworkBuilder::default())
            .executor(SeismicExecutorBuilder::default())
            .consensus(SeismicConsensusBuilder::default())
    }

    /// Instantiates the [`ProviderFactoryBuilder`] for an opstack node.
    ///
    /// # Open a Providerfactory in read-only mode from a datadir
    ///
    /// See also: [`ProviderFactoryBuilder`] and
    /// [`ReadOnlyConfig`](reth_provider::providers::ReadOnlyConfig).
    ///
    /// ```no_run
    /// use reth_chainspec::BASE_MAINNET;
    /// use reth_seismic_node::SeismicNode;
    ///
    /// let factory = SeismicNode::provider_factory_builder()
    ///     .open_read_only(BASE_MAINNET.clone(), "datadir")
    ///     .unwrap();
    /// ```
    ///
    /// # Open a Providerfactory manually with with all required components
    ///
    /// ```no_run
    /// use reth_chainspec::ChainSpecBuilder;
    /// use reth_db::open_db_read_only;
    /// use reth_provider::providers::StaticFileProvider;
    /// use reth_seismic_node::SeismicNode;
    /// use std::sync::Arc;
    ///
    /// let factory = SeismicNode::provider_factory_builder()
    ///     .db(Arc::new(open_db_read_only("db", Default::default()).unwrap()))
    ///     .chainspec(ChainSpecBuilder::base_mainnet().build().into())
    ///     .static_file(StaticFileProvider::read_only("db/static_files", false).unwrap())
    ///     .build_provider_factory();
    /// ```
    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
}

impl<N> Node<N> for SeismicNode
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        SeismicPoolBuilder,
        BasicPayloadServiceBuilder<SeismicPayloadBuilder>,
        SeismicNetworkBuilder,
        SeismicExecutorBuilder,
        SeismicConsensusBuilder,
    >;

    type AddOns = SeismicAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        Self::AddOns::builder().build()
    }
}

impl<N> DebugNode<N> for SeismicNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types_eth::Block<seismic_alloy_consensus::SeismicTxEnvelope>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_node_api::BlockTy<Self> {
        let alloy_rpc_types_eth::Block { header, transactions, .. } = rpc_block;
        reth_seismic_primitives::SeismicBlock {
            header: header.inner,
            body: reth_seismic_primitives::SeismicBlockBody {
                transactions: transactions.into_transactions().map(Into::into).collect(),
                ..Default::default()
            },
        }
    }
}

impl NodeTypes for SeismicNode {
    type Primitives = SeismicPrimitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = SeismicStorage;
}

impl NodeTypesWithEngine for SeismicNode {
    type Payload = SeismicEngineTypes;
}

/// Add-ons w.r.t. optimism.
#[derive(Debug)]
pub struct SeismicAddOns<N: FullNodeComponents>
where
     N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    inner: RpcAddOns<
        N, // Node: ,
        SeismicEthApiBuilder, // EthB: 
        SeismicEngineValidatorBuilder,  // EV: 
    >,
}

impl<N> SeismicAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    /// Build a [`SeismicAddOns`] using [`SeismicAddOnsBuilder`].
    pub fn builder() -> SeismicAddOnsBuilder {
        SeismicAddOnsBuilder::default()
    }
}


/// A regular optimism evm and executor builder.
#[derive(Debug, Default, Clone)]
pub struct SeismicAddOnsBuilder {
}

impl SeismicAddOnsBuilder {
    /// Builds an instance of [`OpAddOns`].
    pub fn build<N>(self) -> SeismicAddOns<N>
    where
        N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
    {
        SeismicAddOns {
            inner: Default::default(),
        }
    }
}


impl<N: FullNodeComponents> Default for SeismicAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    fn default() -> Self {
        Self::builder().build()
    }
}

impl<N> NodeAddOns<N> for SeismicAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type Handle = RpcHandle<N, SeismicEthApi<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        let validation_api = ValidationApi::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            ctx.node.block_executor().clone(),
            ctx.config.rpc.flashbots_config(),
            Box::new(ctx.node.task_executor().clone()),
            Arc::new(SeismicEngineValidator::new(ctx.config.chain.clone())),
        );

        self.inner
            .launch_add_ons_with(ctx, move |modules, _, _| {
                modules.merge_if_module_configured(
                    RethRpcModule::Flashbots,
                    validation_api.into_rpc(),
                )?;

                Ok(())
            })
            .await
    }
}

impl<N> RethRpcAddOns<N> for SeismicAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type EthApi = SeismicEthApi<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N> EngineValidatorAddOn<N> for SeismicAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    SeismicEthApi<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type Validator = SeismicEngineValidator;

    async fn engine_validator(&self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator>
{         SeismicEngineValidatorBuilder::default().build(ctx).await
    }
}

/// A regular optimism evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for SeismicExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>>,
{
    type EVM = SeismicEvmConfig;
    type Executor = BasicBlockExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = SeismicEvmConfig::seismic(ctx.chain_spec());
        let executor = BasicBlockExecutorProvider::new(evm_config.clone());

        Ok((evm_config, executor))
    }
}

/// A basic ethereum transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicPoolBuilder;

impl<Types, Node> PoolBuilder<Node> for SeismicPoolBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type Pool = SeismicTransactionPool<Node::Provider, DiskFileBlobStore>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let data_dir = ctx.config().datadir();
        let pool_config = ctx.pool_config();

        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            blob_cache_size
        } else {
            // get the current blob params for the current timestamp
            let current_timestamp =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or(ctx.chain_spec().blob_params.cancun);

            // Derive the blob cache size from the target blob count, to auto scale it by
            // multiplying it with the slot count for 2 epochs: 384 for pectra
            (blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32
        };

        let custom_config =
            DiskFileBlobStoreConfig::default().with_max_cached_entries(blob_cache_size);

        let blob_store = DiskFileBlobStore::open(data_dir.blobstore(), custom_config)?;
        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .with_head_timestamp(ctx.head().timestamp)
            .kzg_settings(ctx.kzg_settings()?)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let transaction_pool = reth_transaction_pool::Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            blob_store,
            pool_config,
        );
        // info!(target: "reth::cli", "Transaction pool initialized");
        let transactions_path = data_dir.txpool_transactions();

        // spawn txpool maintenance task
        {
            let pool = transaction_pool.clone();
            let chain_events = ctx.provider().canonical_state_stream();
            let client = ctx.provider().clone();
            let transactions_backup_config =

reth_transaction_pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(transactions_path);


            ctx.task_executor().spawn_critical_with_graceful_shutdown_signal(
                "local transactions backup task",
                |shutdown| {
                    reth_transaction_pool::maintain::backup_local_transactions_task(
                        shutdown,
                        pool.clone(),
                        transactions_backup_config,
                    )
                },
            );

            // spawn the maintenance task
            ctx.task_executor().spawn_critical(
                "txpool maintenance task",
                reth_transaction_pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_transaction_pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: transaction_pool.config().max_queued_lifetime,
                        ..Default::default()
                    },
                ),
            );
            // debug!(target: "reth::cli", "Spawned txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}

/// A basic optimism payload service builder
#[derive(Debug, Default, Clone)]
pub struct SeismicPayloadBuilder;

impl SeismicPayloadBuilder {
    /// A helper method initializing [`reth_ethereum_payload_builder::EthereumPayloadBuilder`]
    /// with the given EVM config.
    pub fn build<Types, Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider,
Evm>>     where
        Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>,
        Node: FullNodeTypes<Types = Types>,
        Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>>,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        Types::Payload: PayloadTypes<
            BuiltPayload = EthBuiltPayload<reth_seismic_primitives::SeismicBlock>,
            PayloadAttributes = PayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        let conf = ctx.payload_builder_config();
        Ok(reth_seismic_payload_builder::SeismicPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new().with_gas_limit(conf.gas_limit()),
        ))
    }
}

impl<Types, Node, Pool> PayloadBuilderBuilder<Node, Pool> for SeismicPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Types::Payload: PayloadTypes<
        BuiltPayload = EthBuiltPayload<reth_seismic_primitives::SeismicBlock>,
        PayloadAttributes = PayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    type PayloadBuilder =
        reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider,
SeismicEvmConfig>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::PayloadBuilder> {
        self.build(SeismicEvmConfig::seismic(ctx.chain_spec()), ctx, pool)
    }
}

/// A basic ethereum payload service.
#[derive(Debug, Default, Clone, Copy)]
pub struct SeismicNetworkBuilder {
    // TODO add closure to modify network
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for SeismicNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>>,
    Pool: TransactionPool<
            Transaction: PoolTransaction<Consensus = TxTy<Node::Types>, Pooled =
SeismicTxEnvelope>,
        > + Unpin
        + 'static,
{
    type Primitives = SeismicNetworkPrimitives;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<NetworkHandle<SeismicNetworkPrimitives>> {
        let network = ctx.network_builder().await?;
        let handle = ctx.start_network(network, pool);
        // info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking
        // initialized");
        Ok(handle)
    }
}

/// A basic optimism consensus builder.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for SeismicConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>>,
{
    type Consensus = Arc<dyn FullConsensus<SeismicPrimitives, Error = ConsensusError>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(EthBeaconConsensus::new(ctx.chain_spec())))
    }
}

/// Builder for [`EthereumEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicEngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for SeismicEngineValidatorBuilder
where
    Types: NodeTypesWithEngine<
        ChainSpec = ChainSpec,
        Primitives = SeismicPrimitives,
        Payload = SeismicEngineTypes,
    >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = SeismicEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(SeismicEngineValidator::new(ctx.config.chain.clone()))
    }
}
/// Network primitive types used by Optimism networks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SeismicNetworkPrimitives;

impl NetworkPrimitives for SeismicNetworkPrimitives {
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = alloy_consensus::BlockBody<SeismicTransactionSigned>;
    type Block = alloy_consensus::Block<SeismicTransactionSigned>;
    type BroadcastedTransaction = SeismicTransactionSigned;
    type PooledTransaction = SeismicTxEnvelope;
    type Receipt = SeismicReceipt;
}
