//! Optimism Node types config.

use crate::{
    args::RollupArgs,
    engine::SeismicEngineValidator,
    txpool::{EthTransactionValidator, SeismicTransactionPool},
    SeismicEngineApiBuilder, SeismicEngineTypes,
};
use reth_chainspec::{ChainSpec, EthChainSpec, Hardforks};
use reth_evm::{execute::BasicBlockExecutorProvider, ConfigureEvm, EvmFactory, EvmFactoryFor};
use reth_network::{NetworkConfig, NetworkHandle, NetworkManager, NetworkPrimitives, PeersInfo};
use reth_node_api::{
    AddOnsContext, FullNodeComponents, KeyHasherTy, NodeAddOns, NodePrimitives, PrimitivesTy, TxTy,
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
    BuilderContext, DebugNode, Node, NodeAdapter, NodeComponentsBuilder,
};
use reth_provider::{providers::ProviderFactoryBuilder, CanonStateSubscriptions, EthStorage};
use reth_rpc_api::DebugApiServer;
use reth_rpc_eth_api::ext::L2EthApiExtServer;
use reth_rpc_eth_types::error::FromEvmError;
use reth_rpc_server_types::RethRpcModule;
use reth_seismic_consensus::EthBeaconConsensus;
use reth_seismic_evm::{SeismicEvmConfig, EthNextBlockEnvAttributes};
use reth_seismic_hardforks::OpHardforks;
use reth_seismic_payload_builder::{
    builder::SeismicPayloadTransactions,
    config::{SeismicBuilderConfig, SeismicDAConfig},
};
use reth_seismic_primitives::{
    DepositReceipt, SeismicPrimitives, SeismicReceipt, SeismicTransactionSigned,
};
use reth_seismic_rpc::{
    eth::{ext::SeismicEthExtApi, SeismicEthApiBuilder},
    witness::{DebugExecutionWitnessApiServer, SeismicDebugWitnessApi},
    OpEthApiError, SeismicEthApi, SequencerClient,
};
use reth_seismic_txpool::{
    conditional::MaybeConditionalTransaction,
    interop::MaybeInteropTransaction,
    supervisor::{SupervisorClient, DEFAULT_SUPERVISOR_URL},
    SeismicPooledTx,
};
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, CoinbaseTipOrdering, EthPoolTransaction, PoolTransaction,
    TransactionPool, TransactionValidationTaskExecutor,
};
use reth_trie_db::MerklePatriciaTrie;
use revm::context::TxEnv;
use seismic_alloy_consensus::interop::SafetyLevel;
use std::sync::Arc;

/// Storage implementation for Optimism.
pub type SeismicStorage = EthStorage<SeismicTransactionSigned>;

/// Type configuration for a regular Optimism node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicNode {
    /// Additional Optimism args
    pub args: RollupArgs,
    /// Data availability configuration for the OP builder.
    ///
    /// Used to throttle the size of the data availability payloads (configured by the batcher via
    /// the `miner_` api).
    ///
    /// By default no throttling is applied.
    pub da_config: SeismicDAConfig,
}

impl SeismicNode {
    /// Creates a new instance of the Optimism node type.
    pub fn new(args: RollupArgs) -> Self {
        Self { args, da_config: SeismicDAConfig::default() }
    }

    /// Configure the data availability configuration for the OP builder.
    pub fn with_da_config(mut self, da_config: SeismicDAConfig) -> Self {
        self.da_config = da_config;
        self
    }

    /// Returns the components for the given [`RollupArgs`].
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
        let RollupArgs { disable_txpool_gossip, compute_pending_block, discovery_v4, .. } =
            self.args;
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(
                SeismicPoolBuilder::default()
                    .with_enable_tx_conditional(self.args.enable_tx_conditional)
                    .with_supervisor(
                        self.args.supervisor_http.clone(),
                        self.args.supervisor_safety_level,
                    ),
            )
            .payload(BasicPayloadServiceBuilder::new(
                SeismicPayloadBuilder::new(compute_pending_block)
                    .with_da_config(self.da_config.clone()),
            ))
            .network(SeismicNetworkBuilder {
                disable_txpool_gossip,
                disable_discovery_v4: !discovery_v4,
            })
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
    N: FullNodeTypes<
        Types: NodeTypesWithEngine<
            Payload = SeismicEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
        >,
    >,
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
        Self::AddOns::builder()
            .with_sequencer(self.args.sequencer_http.clone())
            .with_da_config(self.da_config.clone())
            .with_enable_tx_conditional(self.args.enable_tx_conditional)
            .build()
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
pub struct SeismicAddOns<N>
where
    N: FullNodeComponents,
    SeismicEthApiBuilder: EthApiBuilder<N>,
{
    /// Rpc add-ons responsible for launching the RPC servers and instantiating the RPC handlers
    /// and eth-api.
    pub rpc_add_ons: RpcAddOns<
        N,
        SeismicEthApiBuilder,
        SeismicEngineValidatorBuilder,
        SeismicEngineApiBuilder<SeismicEngineValidatorBuilder>,
    >,
    /// Data availability configuration for the OP builder.
    pub da_config: SeismicDAConfig,
    /// Sequencer client, configured to forward submitted transactions to sequencer of given OP
    /// network.
    pub sequencer_client: Option<SequencerClient>,
    /// Enable transaction conditionals.
    enable_tx_conditional: bool,
}

impl<N> Default for SeismicAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<Primitives = SeismicPrimitives>>,
    SeismicEthApiBuilder: EthApiBuilder<N>,
{
    fn default() -> Self {
        Self::builder().build()
    }
}

impl<N> SeismicAddOns<N>
where
    N: FullNodeComponents<Types: NodeTypes<Primitives = SeismicPrimitives>>,
    SeismicEthApiBuilder: EthApiBuilder<N>,
{
    /// Build a [`SeismicAddOns`] using [`SeismicAddOnsBuilder`].
    pub fn builder() -> SeismicAddOnsBuilder {
        SeismicAddOnsBuilder::default()
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
        Evm: ConfigureEvm<NextBlockEnvCtx = EthNextBlockEnvAttributes>,
    >,
    OpEthApiError: FromEvmError<N::Evm>,
    <N::Pool as TransactionPool>::Transaction: SeismicPooledTx,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = op_revm::OpTransaction<TxEnv>>,
{
    type Handle = RpcHandle<N, SeismicEthApi<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        let Self { rpc_add_ons, da_config, sequencer_client, enable_tx_conditional } = self;

        let builder = reth_seismic_payload_builder::SeismicPayloadBuilder::new(
            ctx.node.pool().clone(),
            ctx.node.provider().clone(),
            ctx.node.evm_config().clone(),
        );
        // install additional OP specific rpc methods
        let debug_ext = SeismicDebugWitnessApi::new(
            ctx.node.provider().clone(),
            Box::new(ctx.node.task_executor().clone()),
            builder,
        );

        let tx_conditional_ext: SeismicEthExtApi<N::Pool, N::Provider> = SeismicEthExtApi::new(
            sequencer_client,
            ctx.node.pool().clone(),
            ctx.node.provider().clone(),
        );

        rpc_add_ons
            .launch_add_ons_with(ctx, move |modules, auth_modules, registry| {
                debug!(target: "reth::cli", "Installing debug payload witness rpc endpoint");
                modules.merge_if_module_configured(RethRpcModule::Debug, debug_ext.into_rpc())?;

                // install the debug namespace in the authenticated if configured
                if modules.module_config().contains_any(&RethRpcModule::Debug) {
                    debug!(target: "reth::cli", "Installing debug rpc endpoint");
                    auth_modules.merge_auth_methods(registry.debug_api().into_rpc())?;
                }

                if enable_tx_conditional {
                    // extend the eth namespace if configured in the regular http server
                    modules.merge_if_module_configured(
                        RethRpcModule::Eth,
                        tx_conditional_ext.into_rpc(),
                    )?;
                }

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
        Evm: ConfigureEvm<NextBlockEnvCtx = EthNextBlockEnvAttributes>,
    >,
    OpEthApiError: FromEvmError<N::Evm>,
    <<N as FullNodeComponents>::Pool as TransactionPool>::Transaction: SeismicPooledTx,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = op_revm::OpTransaction<TxEnv>>,
{
    type EthApi = SeismicEthApi<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.rpc_add_ons.hooks_mut()
    }
}

impl<N> EngineValidatorAddOn<N> for SeismicAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Payload = SeismicEngineTypes,
        >,
    >,
    SeismicEthApiBuilder: EthApiBuilder<N>,
{
    type Validator = SeismicEngineValidator<N::Provider>;

    async fn engine_validator(&self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        SeismicEngineValidatorBuilder::default().build(ctx).await
    }
}

/// A regular optimism evm and executor builder.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicAddOnsBuilder {
    /// Sequencer client, configured to forward submitted transactions to sequencer of given OP
    /// network.
    sequencer_client: Option<SequencerClient>,
    /// Data availability configuration for the OP builder.
    da_config: Option<SeismicDAConfig>,
    /// Enable transaction conditionals.
    enable_tx_conditional: bool,
}

impl SeismicAddOnsBuilder {
    /// With a [`SequencerClient`].
    pub fn with_sequencer(mut self, sequencer_client: Option<String>) -> Self {
        self.sequencer_client = sequencer_client.map(SequencerClient::new);
        self
    }

    /// Configure the data availability configuration for the OP builder.
    pub fn with_da_config(mut self, da_config: SeismicDAConfig) -> Self {
        self.da_config = Some(da_config);
        self
    }

    /// Configure if transaction conditional should be enabled.
    pub fn with_enable_tx_conditional(mut self, enable_tx_conditional: bool) -> Self {
        self.enable_tx_conditional = enable_tx_conditional;
        self
    }
}

impl SeismicAddOnsBuilder {
    /// Builds an instance of [`SeismicAddOns`].
    pub fn build<N>(self) -> SeismicAddOns<N>
    where
        N: FullNodeComponents<Types: NodeTypes<Primitives = SeismicPrimitives>>,
        SeismicEthApiBuilder: EthApiBuilder<N>,
    {
        let Self { sequencer_client, da_config, enable_tx_conditional } = self;

        let sequencer_client_clone = sequencer_client.clone();
        SeismicAddOns {
            rpc_add_ons: RpcAddOns::new(
                SeismicEthApiBuilder::default().with_sequencer(sequencer_client_clone),
                Default::default(),
                Default::default(),
            ),
            da_config: da_config.unwrap_or_default(),
            sequencer_client,
            enable_tx_conditional,
        }
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
        let evm_config = SeismicEvmConfig::optimism(ctx.chain_spec());
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
pub struct SeismicPoolBuilder {
    // TODO add options for txpool args
}

impl<Types, Node> PoolBuilder<Node> for SeismicPoolBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore>;

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

        let transaction_pool =
            reth_transaction_pool::Pool::eth_pool(validator, blob_store, pool_config);
        info!(target: "reth::cli", "Transaction pool initialized");
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
            debug!(target: "reth::cli", "Spawned txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}

/// A basic optimism payload service builder
#[derive(Debug, Default, Clone)]
pub struct SeismicPayloadBuilder<Txs = ()> {
    /// By default the pending block equals the latest block
    /// to save resources and not leak txs from the tx-pool,
    /// this flag enables computing of the pending block
    /// from the tx-pool instead.
    ///
    /// If `compute_pending_block` is not enabled, the payload builder
    /// will use the payload attributes from the latest block. Note
    /// that this flag is not yet functional.
    pub compute_pending_block: bool,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
    /// This data availability configuration specifies constraints for the payload builder
    /// when assembling payloads
    pub da_config: SeismicDAConfig,
}

impl SeismicPayloadBuilder {
    /// Create a new instance with the given `compute_pending_block` flag and data availability
    /// config.
    pub fn new(compute_pending_block: bool) -> Self {
        Self { compute_pending_block, best_transactions: (), da_config: SeismicDAConfig::default() }
    }

    /// Configure the data availability configuration for the OP payload builder.
    pub fn with_da_config(mut self, da_config: SeismicDAConfig) -> Self {
        self.da_config = da_config;
        self
    }
}

impl<Txs> SeismicPayloadBuilder<Txs> {
    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T>(self, best_transactions: T) -> SeismicPayloadBuilder<T> {
        let Self { compute_pending_block, da_config, .. } = self;
        SeismicPayloadBuilder { compute_pending_block, best_transactions, da_config }
    }

    /// A helper method to initialize [`reth_seismic_payload_builder::SeismicPayloadBuilder`] with
    /// the given EVM config.
    pub fn build<Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<
        reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider, Evm, Txs>,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<
                Payload = SeismicEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SeismicPrimitives,
            >,
        >,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        Evm: ConfigureEvm<Primitives = PrimitivesTy<Node::Types>>,
        Txs: SeismicPayloadTransactions<Pool::Transaction>,
    {
        let payload_builder =
            reth_seismic_payload_builder::SeismicPayloadBuilder::with_builder_config(
                pool,
                ctx.provider().clone(),
                evm_config,
                SeismicBuilderConfig { da_config: self.da_config.clone() },
            )
            .with_transactions(self.best_transactions.clone())
            .set_compute_pending_block(self.compute_pending_block);
        Ok(payload_builder)
    }
}

impl<Node, Pool, Txs> PayloadBuilderBuilder<Node, Pool> for SeismicPayloadBuilder<Txs>
where
    Node: FullNodeTypes<
        Types: NodeTypesWithEngine<
            Payload = SeismicEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
        >,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Txs: SeismicPayloadTransactions<Pool::Transaction>,
    <Pool as TransactionPool>::Transaction: SeismicPooledTx,
{
    type PayloadBuilder = reth_seismic_payload_builder::SeismicPayloadBuilder<
        Pool,
        Node::Provider,
        SeismicEvmConfig,
        Txs,
    >;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::PayloadBuilder> {
        self.build(SeismicEvmConfig::optimism(ctx.chain_spec()), ctx, pool)
    }
}

/// A basic optimism network builder.
#[derive(Debug, Default, Clone)]
pub struct SeismicNetworkBuilder {
    /// Disable transaction pool gossip
    pub disable_txpool_gossip: bool,
    /// Disable discovery v4
    pub disable_discovery_v4: bool,
}

impl SeismicNetworkBuilder {
    /// Returns the [`NetworkConfig`] that contains the settings to launch the p2p network.
    ///
    /// This applies the configured [`SeismicNetworkBuilder`] settings.
    pub fn network_config<Node>(
        &self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<NetworkConfig<<Node as FullNodeTypes>::Provider, SeismicNetworkPrimitives>>
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    {
        let Self { disable_txpool_gossip, disable_discovery_v4 } = self.clone();
        let args = &ctx.config().network;
        let network_builder = ctx
            .network_config_builder()?
            // apply discovery settings
            .apply(|mut builder| {
                let rlpx_socket = (args.addr, args.port).into();
                if disable_discovery_v4 || args.discovery.disable_discovery {
                    builder = builder.disable_discv4_discovery();
                }
                if !args.discovery.disable_discovery {
                    builder = builder.discovery_v5(
                        args.discovery.discovery_v5_builder(
                            rlpx_socket,
                            ctx.config()
                                .network
                                .resolved_bootnodes()
                                .or_else(|| ctx.chain_spec().bootnodes())
                                .unwrap_or_default(),
                        ),
                    );
                }

                builder
            });

        let mut network_config = ctx.build_network_config(network_builder);

        // When `sequencer_endpoint` is configured, the node will forward all transactions to a
        // Sequencer node for execution and inclusion on L1, and disable its own txpool
        // gossip to prevent other parties in the network from learning about them.
        network_config.tx_gossip_disabled = disable_txpool_gossip;

        Ok(network_config)
    }
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for SeismicNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>>,
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TxTy<Node::Types>,
                Pooled = EthPooledTransaction<SeismicTransactionSigned>,
            >,
        > + Unpin
        + 'static,
{
    type Primitives = SeismicNetworkPrimitives;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<NetworkHandle<Self::Primitives>> {
        let network_config = self.network_config(ctx)?;
        let network = NetworkManager::builder(network_config).await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");

        Ok(handle)
    }
}

/// A basic optimism consensus builder.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for SeismicConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec: OpHardforks,
            Primitives: NodePrimitives<Receipt: DepositReceipt>,
        >,
    >,
{
    type Consensus = Arc<EthBeaconConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(EthBeaconConsensus::new(ctx.chain_spec())))
    }
}

/// Builder for [`SeismicEngineValidator`].
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
    type Validator = SeismicEngineValidator<Node::Provider>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(SeismicEngineValidator::new::<KeyHasherTy<Types>>(
            ctx.config.chain.clone(),
            ctx.node.provider().clone(),
        ))
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
    type PooledTransaction = EthPooledTransaction<SeismicTransactionSigned>;
    type Receipt = SeismicReceipt;
}
