//! Seismic Node types config.

use crate::{
    engine::{SeismicEngineTypes, SeismicEngineValidator},
    txpool::SeismicTransactionPool,
};
use alloy_eips::merge::EPOCH_SLOTS;
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_consensus::{ConsensusError, FullConsensus};
use reth_engine_primitives::{NoopInvalidBlockHook, TreeConfig};
use reth_eth_wire_types::NewBlock;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmFactory, EvmFactoryFor, NextBlockEnvAttributes,
};
use reth_network::{NetworkHandle, NetworkPrimitives};
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeAddOns, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NetworkBuilder, PayloadBuilderBuilder, PoolBuilder,
    },
    node::{FullNodeTypes, NodeTypes},
    rpc::{
        BasicEngineApiBuilder, BasicEngineValidator, BasicEngineValidatorBuilder, EngineApiBuilder,
        EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, PayloadValidatorBuilder,
        RethRpcAddOns, RethRpcMiddleware, RpcAddOns, RpcHandle, RpcModuleContainer,
    },
    BuilderContext, DebugNode, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig,
};
use reth_node_ethereum::consensus::EthBeaconConsensus;
use reth_payload_primitives::PayloadAttributesBuilder;
use reth_provider::{providers::ProviderFactoryBuilder, CanonStateSubscriptions, EthStorage};
use reth_rpc::ValidationApi;
use reth_rpc_api::BlockSubmissionValidationApiServer;
use reth_rpc_builder::{config::RethRpcServerConfig, Identity};
use reth_rpc_eth_api::helpers::{
    config::{EthConfigApiServer, EthConfigHandler},
    FullEthApi,
};
use reth_rpc_eth_types::{
    error::{api::FromEvmHalt, FromEvmError},
    EthApiError,
};
use reth_rpc_server_types::RethRpcModule;
use reth_seismic_evm::SeismicEvmConfig;
use reth_seismic_payload_builder::SeismicBuilderConfig;
use reth_seismic_primitives::{SeismicPrimitives, SeismicReceipt, SeismicTransactionSigned};
use reth_seismic_rpc::{
    ext::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer},
    SeismicEthApiBuilder, SeismicEthApiError, SeismicRethWithSignable,
};
use reth_transaction_pool::{
    blobstore::{DiskFileBlobStore, DiskFileBlobStoreConfig},
    CoinbaseTipOrdering, PoolTransaction, TransactionPool, TransactionValidationTaskExecutor,
};
use revm::context::TxEnv;
use seismic_alloy_consensus::SeismicTxEnvelope;
use std::{sync::Arc, time::SystemTime};

use crate::{purpose_keys::get_purpose_keys, seismic_evm_config};

/// Storage implementation for Seismic.
pub type SeismicStorage = EthStorage<SeismicTransactionSigned>;

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
/// Type configuration for a regular Seismic node.
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
            Types: NodeTypes<
                Payload = SeismicEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SeismicPrimitives,
            >,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(SeismicPoolBuilder::default())
            .executor(SeismicExecutorBuilder::default())
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
    N: FullNodeTypes<
        Types: NodeTypes<
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
        SeismicEthApiBuilder<SeismicRethWithSignable>,
        SeismicEngineValidatorBuilder,
        BasicEngineApiBuilder<SeismicEngineValidatorBuilder>,
        BasicEngineValidatorBuilder<SeismicEngineValidatorBuilder>,
        Identity,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        Self::AddOns::builder().build::<
            NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
            SeismicEthApiBuilder<SeismicRethWithSignable>,
            SeismicEngineValidatorBuilder,
            BasicEngineApiBuilder<SeismicEngineValidatorBuilder>,
            BasicEngineValidatorBuilder<SeismicEngineValidatorBuilder>,
            Identity
        >()
    }
}

impl NodeTypes for SeismicNode {
    type Primitives = SeismicPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = SeismicStorage;
    type Payload = SeismicEngineTypes;
}

impl SeismicNode {
    /// Converts a fetched RPC block into a Seismic primitive block, preserving the full block
    /// body (transactions, withdrawals, ...) instead of rebuilding it from transactions alone.
    fn rpc_block_to_primitive(
        rpc_block: alloy_rpc_types_eth::Block<seismic_alloy_consensus::SeismicTxEnvelope>,
    ) -> reth_seismic_primitives::SeismicBlock {
        rpc_block.into_consensus().convert_transactions()
    }
}

impl<N> DebugNode<N> for SeismicNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types_eth::Block<seismic_alloy_consensus::SeismicTxEnvelope>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_node_api::BlockTy<Self> {
        Self::rpc_block_to_primitive(rpc_block)
    }

    fn local_payload_attributes_builder(
            chain_spec: &Self::ChainSpec,
        ) -> impl PayloadAttributesBuilder<
            <<Self as reth_node_api::NodeTypes>::Payload as reth_node_api::PayloadTypes>::PayloadAttributes,
    >{
        reth_engine_local::LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// Helper trait alias that bundles the common `FullNodeComponents` bounds required by Seismic
/// add-ons. This avoids repeating the verbose `NodeTypes` and `Evm` constraints across every
/// `impl` block.
pub trait SeismicFullNode:
    FullNodeComponents<
    Types: NodeTypes<
        ChainSpec = ChainSpec,
        Primitives = SeismicPrimitives,
        Storage = SeismicStorage,
        Payload = SeismicEngineTypes,
    >,
    Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
>
{
}

impl<N> SeismicFullNode for N where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Storage = SeismicStorage,
            Payload = SeismicEngineTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >
{
}

/// Add-ons w.r.t. seismic
#[derive(Debug)]
pub struct SeismicAddOns<
    N: FullNodeComponents,
    EthB: EthApiBuilder<N> = SeismicEthApiBuilder<SeismicRethWithSignable>,
    PVB = SeismicEngineValidatorBuilder,
    EB = BasicEngineApiBuilder<SeismicEngineValidatorBuilder>,
    EVB = BasicEngineValidatorBuilder<SeismicEngineValidatorBuilder>,
    RpcMiddleware = Identity,
> {
    inner: RpcAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>,
}

impl<N, EthB, PVB, EB, EVB, RpcMiddleware> SeismicAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>
where
    N: SeismicFullNode,
    EthB: EthApiBuilder<N>,
{
    /// Build a [`SeismicAddOns`] using [`SeismicAddOnsBuilder`].
    pub fn builder() -> SeismicAddOnsBuilder {
        SeismicAddOnsBuilder::default()
    }
}

/// A regular seismic evm and executor builder.
#[derive(Debug, Default, Clone)]
pub struct SeismicAddOnsBuilder {}

impl SeismicAddOnsBuilder {
    /// Builds an instance of [`SeismicAddOns`].
    pub fn build<N, EthB, PVB, EB, EVB, RpcMiddleware>(
        self,
    ) -> SeismicAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>
    where
        N: SeismicFullNode,
        EthB: EthApiBuilder<N> + Default,
        PVB: Default,
        EB: Default,
        EVB: Default,
        RpcMiddleware: Default,
    {
        SeismicAddOns {
            inner: RpcAddOns::new(
                EthB::default(),
                PVB::default(),
                EB::default(),
                EVB::default(),
                RpcMiddleware::default(),
            ),
        }
    }
}

impl<N> Default for SeismicAddOns<N>
where
    N: SeismicFullNode,
    SeismicEthApiBuilder<SeismicRethWithSignable>: EthApiBuilder<N>,
{
    fn default() -> Self {
        Self::builder().build::<
            N,
            SeismicEthApiBuilder<SeismicRethWithSignable>,
            SeismicEngineValidatorBuilder,
            BasicEngineApiBuilder<SeismicEngineValidatorBuilder>,
            BasicEngineValidatorBuilder<SeismicEngineValidatorBuilder>,
            Identity
        >()
    }
}

impl<N, EthB, PVB, EB, EVB, RpcMiddleware> NodeAddOns<N>
    for SeismicAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>
where
    N: SeismicFullNode,
    EthB: EthApiBuilder<N>,
    EthB::EthApi: FullEthApi + Send + Sync + 'static,
    <EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::Error: Send + Sync + 'static,
    jsonrpsee::types::ErrorObject<'static>:
        From<<EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::Error>,
    <<EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::NetworkTypes as reth_rpc_eth_api::RpcTypes>::TransactionRequest:
        From<alloy_rpc_types::TransactionRequest>
            + AsRef<alloy_rpc_types::TransactionRequest>
            + Send
            + Sync
            + 'static,
    PVB: PayloadValidatorBuilder<N>,
    EB: EngineApiBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    RpcMiddleware: RethRpcMiddleware,
    EthApiError: FromEvmError<N::Evm>,
    SeismicEthApiError:
        FromEvmError<N::Evm> + FromEvmHalt<<EvmFactoryFor<N::Evm> as EvmFactory>::HaltReason>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = seismic_revm::SeismicTransaction<TxEnv>>,
{
    type Handle = RpcHandle<N, EthB::EthApi>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        let validation_api = ValidationApi::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            ctx.node.evm_config().clone(),
            ctx.config.rpc.flashbots_config(),
            Box::new(ctx.node.task_executor().clone()),
            Arc::new(SeismicEngineValidator::new(ctx.config.chain.clone())),
        );

        let eth_config =
            EthConfigHandler::new(ctx.node.provider().clone(), ctx.node.evm_config().clone());

        let purpose_keys = get_purpose_keys().clone();

        self.inner
            .launch_add_ons_with(ctx, move |container| {
                let RpcModuleContainer { modules, registry, .. } = container;
                modules.merge_if_module_configured(
                    RethRpcModule::Flashbots,
                    validation_api.into_rpc(),
                )?;

                modules.merge_if_module_configured(RethRpcModule::Eth, eth_config.into_rpc())?;

                // Register Seismic eth_ overrides (sendRawTransaction, call, estimateGas, etc.)
                modules.replace_configured(
                    EthApiExt::new(registry.eth_api().clone(), purpose_keys.clone()).into_rpc(),
                )?;

                // Register seismic_ namespace (getTeePublicKey)
                modules.merge_configured(SeismicApi::new(purpose_keys).into_rpc())?;

                // Trace endpoints stay off on Seismic. Our traces are already sanitized
                // (calldata, return data, memory, and stack are stripped — see
                // https://github.com/SeismicSystems/seismic-revm-inspectors/blob/seismic/README.md),
                // but the leftover metadata (gas, revert paths, call-tree shape, touched
                // addresses) is still a side channel on private state. So to be 100% sure,
                // we just don't serve these namespaces at all, whatever the operator's
                // `--http.api` says:
                //   - debug_*: geth-style tracing, plus raw state/DB access
                //   - trace_*: parity-style tracing (also honors a caller-supplied `from`)
                //   - ots_*:   Otterscan, which wraps the same tracing internals
                // We may re-enable (sanitized) tracing here someday if needed.
                for module in [RethRpcModule::Debug, RethRpcModule::Trace, RethRpcModule::Ots] {
                    let method_names: Vec<&'static str> = modules
                        .methods_by_module::<fn(&str) -> bool>(module)
                        .method_names()
                        .collect();
                    for name in method_names {
                        modules.remove_method_from_configured(name);
                    }
                }

                Ok(())
            })
            .await
    }
}

impl<N, EthB, PVB, EB, EVB, RpcMiddleware> RethRpcAddOns<N>
    for SeismicAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>
where
    N: SeismicFullNode,
    EthB: EthApiBuilder<N>,
    EthB::EthApi: FullEthApi + Send + Sync + 'static,
    <EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::Error: Send + Sync + 'static,
    jsonrpsee::types::ErrorObject<'static>:
        From<<EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::Error>,
    <<EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::NetworkTypes as reth_rpc_eth_api::RpcTypes>::TransactionRequest:
        From<alloy_rpc_types::TransactionRequest>
            + AsRef<alloy_rpc_types::TransactionRequest>
            + Send
            + Sync
            + 'static,
    PVB: PayloadValidatorBuilder<N>,
    EB: EngineApiBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    RpcMiddleware: RethRpcMiddleware,
    EthApiError: FromEvmError<N::Evm>,
    SeismicEthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = seismic_revm::SeismicTransaction<TxEnv>>,
{
    type EthApi = EthB::EthApi;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N, EthB, PVB, EB, EVB, RpcMiddleware> EngineValidatorAddOn<N>
    for SeismicAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>
where
    N: SeismicFullNode<Evm: ConfigureEngineEvm<ExecutionData>>,
    EthB: EthApiBuilder<N>,
    EthB::EthApi: FullEthApi + Send + Sync + 'static,
    <EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::Error: Send + Sync + 'static,
    jsonrpsee::types::ErrorObject<'static>:
        From<<EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::Error>,
    <<EthB::EthApi as reth_rpc_eth_api::EthApiTypes>::NetworkTypes as reth_rpc_eth_api::RpcTypes>::TransactionRequest:
        From<alloy_rpc_types::TransactionRequest>
            + AsRef<alloy_rpc_types::TransactionRequest>
            + Send
            + Sync
            + 'static,
    PVB: PayloadValidatorBuilder<N>,
    EB: EngineApiBuilder<N>,
    EVB: EngineValidatorBuilder<N> + Send,
    RpcMiddleware: Send,
{
    type ValidatorBuilder = EVB;

    fn engine_validator_builder(&self) -> Self::ValidatorBuilder {
        EngineValidatorAddOn::engine_validator_builder(&self.inner)
    }
}

/// A regular seismic evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for SeismicExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = SeismicPrimitives>>,
{
    type EVM = SeismicEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let purpose_keys = crate::purpose_keys::get_purpose_keys();
        let evm_config = seismic_evm_config(ctx.chain_spec(), purpose_keys);

        Ok(evm_config)
    }
}

/// A basic ethereum transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicPoolBuilder;

impl<Node> PoolBuilder<Node> for SeismicPoolBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            Payload = SeismicEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
        >,
    >,
    // T: EthPoolTransaction<Consensus = TxTy<Node::Types>>
    // + MaybeConditionalTransaction
    // + MaybeInteropTransaction,
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
        let head_timestamp_seconds = if cfg!(feature = "timestamp-in-seconds") {
            ctx.head().timestamp
        } else {
            ctx.head().timestamp / 1000
        };
        let eth_validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .with_head_timestamp(head_timestamp_seconds)
            .kzg_settings(ctx.kzg_settings()?)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            // Gas is paid in USDC on Seismic, not native ETH. Disable the native balance check
            // so transactions from accounts with zero ETH are not rejected. Actual gas payment
            // is enforced by the Seismic revm implementation at execution time.
            .disable_balance_check()
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        // Wrap the eth validator with seismic-specific validation
        let validator = eth_validator.map(reth_seismic_txpool::SeismicTransactionValidator::new);

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

            // spawn the maintenance task with USDC balance augmentation
            let balance_hook = reth_seismic_txpool::SeismicBalanceHook;
            ctx.task_executor().spawn_critical(
                "txpool maintenance task",
                reth_transaction_pool::maintain::maintain_transaction_pool_future_with_hook(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_transaction_pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: transaction_pool.config().max_queued_lifetime,
                        ..Default::default()
                    },
                    balance_hook,
                ),
            );
            // debug!(target: "reth::cli", "Spawned txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}

/// A basic seismic payload service builder
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
    ) -> eyre::Result<reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider, Evm>>
    where
        Node: FullNodeTypes<
            Types: NodeTypes<
                Payload = SeismicEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SeismicPrimitives,
            >,
        >,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        Evm: ConfigureEvm<Primitives = PrimitivesTy<Node::Types>>,
        // Txs: SeismicPayloadTransactions<Pool::Transaction>,
    {
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);

        Ok(reth_seismic_payload_builder::SeismicPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            SeismicBuilderConfig::new().with_gas_limit(gas_limit),
        ))
    }
}

impl<Node, Pool> PayloadBuilderBuilder<Node, Pool, SeismicEvmConfig> for SeismicPayloadBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            Payload = SeismicEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
        >,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type PayloadBuilder =
        reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider, SeismicEvmConfig>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: SeismicEvmConfig,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);

        let payload_builder = reth_seismic_payload_builder::SeismicPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            SeismicBuilderConfig::new().with_gas_limit(gas_limit),
        );
        Ok(payload_builder)
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
            Transaction: PoolTransaction<Consensus = TxTy<Node::Types>, Pooled = SeismicTxEnvelope>, /* equiv to op_alloy_consensus::OpPooledTransaction>, */
        > + Unpin
        + 'static,
{
    type Network = NetworkHandle<SeismicNetworkPrimitives>;

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

/// A basic seismic consensus builder.
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
    Types: NodeTypes<
        ChainSpec = ChainSpec,
        Primitives = SeismicPrimitives,
        Payload = SeismicEngineTypes,
    >,
    Node: FullNodeComponents<Types = Types>,
    Node::Evm: ConfigureEngineEvm<ExecutionData>,
{
    type EngineValidator = BasicEngineValidator<Node::Provider, Node::Evm, SeismicEngineValidator>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
    ) -> eyre::Result<Self::EngineValidator> {
        let seismic_validator = SeismicEngineValidator::new(ctx.config.chain.clone());
        Ok(BasicEngineValidator::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            ctx.node.evm_config().clone(),
            seismic_validator,
            tree_config,
            Box::new(NoopInvalidBlockHook::default()),
        ))
    }
}

impl<Node> PayloadValidatorBuilder<Node> for SeismicEngineValidatorBuilder
where
    Node: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = SeismicPrimitives,
            Payload = SeismicEngineTypes,
        >,
    >,
{
    type Validator = SeismicEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(SeismicEngineValidator::new(ctx.config.chain.clone()))
    }
}
/// Network primitive types used by Seismic network.
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
    type NewBlockPayload = NewBlock<Self::Block>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip4895::{Withdrawal, Withdrawals};
    use alloy_primitives::Address;
    use alloy_rpc_types_eth::{BlockTransactions, Header};

    #[test]
    fn rpc_to_primitive_block_preserves_withdrawals() {
        let withdrawals = Withdrawals(vec![Withdrawal {
            index: 1,
            validator_index: 2,
            address: Address::repeat_byte(0xab),
            amount: 42,
        }]);
        let rpc_block = alloy_rpc_types_eth::Block::<SeismicTxEnvelope> {
            header: Header::default(),
            uncles: Vec::new(),
            transactions: BlockTransactions::Full(Vec::new()),
            withdrawals: Some(withdrawals.clone()),
        };

        let primitive = SeismicNode::rpc_block_to_primitive(rpc_block);
        assert_eq!(primitive.body.withdrawals, Some(withdrawals));
    }
}
