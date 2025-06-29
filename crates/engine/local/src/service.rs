//! Provides a local dev service engine that can be used to run a dev chain.
//!
//! [`LocalEngineService`] polls the payload builder based on a mining mode
//! which can be set to `Instant` or `Interval`. The `Instant` mode will
//! constantly poll the payload builder and initiate block building
//! with a single transaction. The `Interval` mode will initiate block
//! building at a fixed interval.

use core::fmt;
use std::{
    fmt::{Debug, Formatter},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::miner::{LocalMiner, MiningMode};
use futures_util::{Stream, StreamExt};
use reth_chainspec::EthChainSpec;
use reth_consensus::{ConsensusError, FullConsensus};
use reth_engine_primitives::{BeaconConsensusEngineEvent, BeaconEngineMessage, EngineValidator};
use reth_engine_service::service::EngineMessageStream;
use reth_engine_tree::{
    backup::BackupHandle,
    chain::{ChainEvent, HandlerEvent},
    engine::{
        EngineApiKind, EngineApiRequest, EngineApiRequestHandler, EngineRequestHandler, FromEngine,
        RequestHandlerEvent,
    },
    persistence::PersistenceHandle,
    tree::{EngineApiTreeHandler, InvalidBlockHook, TreeConfig},
};
use reth_evm::ConfigureEvm;
use reth_node_types::BlockTy;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{PayloadAttributesBuilder, PayloadTypes};
use reth_provider::{
    providers::{BlockchainProvider, ProviderNodeTypes},
    ChainSpecProvider, ProviderFactory,
};
use reth_prune::PrunerWithFactory;
use reth_stages_api::MetricEventsSender;
use tokio::sync::mpsc::UnboundedSender;
use tracing::error;

// seismic imports not used by upstream
use reth_node_core::dirs::{ChainPath, DataDirPath};

/// Provides a local dev service engine that can be used to drive the
/// chain forward.
///
/// This service both produces and consumes [`BeaconEngineMessage`]s. This is done to allow
/// modifications of the stream
pub struct LocalEngineService<N>
where
    N: ProviderNodeTypes,
{
    /// Processes requests.
    ///
    /// This type is responsible for processing incoming requests.
    handler: EngineApiRequestHandler<EngineApiRequest<N::Payload, N::Primitives>, N::Primitives>,
    /// Receiver for incoming requests (from the engine API endpoint) that need to be processed.
    incoming_requests: EngineMessageStream<N::Payload>,
}

impl<N> LocalEngineService<N>
where
    N: ProviderNodeTypes,
{
    /// Constructor for [`LocalEngineService`].
    #[expect(clippy::too_many_arguments)]
    pub fn new<B, V, C>(
        consensus: Arc<dyn FullConsensus<N::Primitives, Error = ConsensusError>>,
        provider: ProviderFactory<N>,
        blockchain_db: BlockchainProvider<N>,
        pruner: PrunerWithFactory<ProviderFactory<N>>,
        payload_builder: PayloadBuilderHandle<N::Payload>,
        payload_validator: V,
        tree_config: TreeConfig,
        invalid_block_hook: Box<dyn InvalidBlockHook<N::Primitives>>,
        sync_metrics_tx: MetricEventsSender,
        to_engine: UnboundedSender<BeaconEngineMessage<N::Payload>>,
        from_engine: EngineMessageStream<N::Payload>,
        mode: MiningMode,
        payload_attributes_builder: B,
        evm_config: C,
        data_dir: ChainPath<DataDirPath>,
    ) -> Self
    where
        B: PayloadAttributesBuilder<<N::Payload as PayloadTypes>::PayloadAttributes>,
        V: EngineValidator<N::Payload, Block = BlockTy<N>>,
        C: ConfigureEvm<Primitives = N::Primitives> + 'static,
    {
        let chain_spec = provider.chain_spec();
        let engine_kind =
            if chain_spec.is_optimism() { EngineApiKind::OpStack } else { EngineApiKind::Ethereum };

        let persistence_handle =
            PersistenceHandle::<N::Primitives>::spawn_service(provider, pruner, sync_metrics_tx);
        let canonical_in_memory_state = blockchain_db.canonical_in_memory_state();
        let backup_handle = BackupHandle::spawn_service(data_dir);

        let (to_tree_tx, from_tree) = EngineApiTreeHandler::<N::Primitives, _, _, _, _>::spawn_new(
            blockchain_db.clone(),
            consensus,
            payload_validator,
            persistence_handle,
            payload_builder.clone(),
            canonical_in_memory_state,
            tree_config,
            invalid_block_hook,
            engine_kind,
            evm_config,
            backup_handle,
        );

        let handler = EngineApiRequestHandler::new(to_tree_tx, from_tree);

        LocalMiner::spawn_new(
            blockchain_db,
            payload_attributes_builder,
            to_engine,
            mode,
            payload_builder,
        );

        Self { handler, incoming_requests: from_engine }
    }
}

impl<N> Stream for LocalEngineService<N>
where
    N: ProviderNodeTypes,
{
    type Item = ChainEvent<BeaconConsensusEngineEvent<N::Primitives>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Poll::Ready(ev) = this.handler.poll(cx) {
            return match ev {
                RequestHandlerEvent::HandlerEvent(ev) => match ev {
                    HandlerEvent::BackfillAction(_) => {
                        error!(target: "engine::local", "received backfill request in local engine");
                        Poll::Ready(Some(ChainEvent::FatalError))
                    }
                    HandlerEvent::Event(ev) => Poll::Ready(Some(ChainEvent::Handler(ev))),
                    HandlerEvent::FatalError => Poll::Ready(Some(ChainEvent::FatalError)),
                },
                RequestHandlerEvent::Download(_) => {
                    error!(target: "engine::local", "received download request in local engine");
                    Poll::Ready(Some(ChainEvent::FatalError))
                }
            }
        }

        // forward incoming requests to the handler
        while let Poll::Ready(Some(req)) = this.incoming_requests.poll_next_unpin(cx) {
            this.handler.on_event(FromEngine::Request(req.into()));
        }

        Poll::Pending
    }
}

impl<N: ProviderNodeTypes> Debug for LocalEngineService<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEngineService").finish_non_exhaustive()
    }
}
