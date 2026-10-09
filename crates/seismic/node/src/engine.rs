//! Seismic engine API types, validators and the authenticated `engine_` RPC server.
//!
//! Seismic blocks carry a sub-second timestamp component, so the Engine API payload attributes
//! and execution payloads are the extended types from [`reth_seismic_engine_primitives`]. The
//! server exposes the Cancun/Prague method versions only; Seismic chains are post-Prague from
//! genesis.

use alloy_consensus::BlockHeader;
use alloy_eips::eip7685::{Requests, RequestsOrHash};
use alloy_primitives::{BlockHash, B256, U64};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ClientVersionV1, ExecutionPayloadBodiesV1, ExecutionPayloadEnvelopeV2,
    ExecutionPayloadEnvelopeV5, ExecutionPayloadV1, ForkchoiceState, ForkchoiceUpdated,
    PayloadError, PayloadId, PayloadStatus, PraguePayloadFields,
};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee_core::{server::RpcModule, RpcResult};
use reth_chainspec::EthereumHardforks;
use reth_engine_primitives::{EngineTypes, PayloadValidator};
use reth_node_api::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineApiValidator, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_payload_primitives::{InvalidPayloadAttributesError, PayloadTypes};
use reth_payload_validator::{cancun, prague, shanghai};
use reth_primitives_traits::{Block as _, RecoveredBlock, SealedBlock};
use reth_rpc_api::IntoEngineApiRpcModule;
use reth_rpc_engine_api::EngineApi;
use reth_seismic_chainspec::SeismicChainSpec;
use reth_seismic_engine_primitives::{
    SeismicBuiltPayload, SeismicExecutionData, SeismicExecutionPayloadEnvelopeV3,
    SeismicExecutionPayloadEnvelopeV4, SeismicExecutionPayloadV3, SeismicPayloadAttributes,
    SeismicPayloadBuilderAttributes,
};
use reth_seismic_primitives::{SeismicBlock, SeismicHeader};
use reth_storage_api::{BlockReader, HeaderProvider, StateProviderFactory};
use reth_transaction_pool::TransactionPool;
use std::sync::Arc;
use tracing::trace;

/// The list of all supported Engine capabilities available over the engine endpoint.
pub const SEISMIC_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV3",
    "engine_getClientVersionV1",
    "engine_getPayloadV3",
    "engine_getPayloadV4",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_getPayloadBodiesByHashV1",
    "engine_getPayloadBodiesByRangeV1",
];

/// The types used by the Seismic beacon consensus engine.
#[derive(Debug, Default, Clone, Copy, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct SeismicEngineTypes;

impl PayloadTypes for SeismicEngineTypes {
    type ExecutionData = SeismicExecutionData;
    type BuiltPayload = SeismicBuiltPayload;
    type PayloadAttributes = SeismicPayloadAttributes;
    type PayloadBuilderAttributes = SeismicPayloadBuilderAttributes;

    fn block_to_payload(block: SealedBlock<SeismicBlock>) -> Self::ExecutionData {
        SeismicExecutionData::from_sealed_block(block)
    }
}

impl EngineTypes for SeismicEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = SeismicExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = SeismicExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
}

/// Validator for the Seismic engine API.
#[derive(Debug, Clone)]
pub struct SeismicEngineValidator {
    chain_spec: Arc<SeismicChainSpec>,
}

impl SeismicEngineValidator {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<SeismicChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &SeismicChainSpec {
        &self.chain_spec
    }

    /// Ensures that the given payload does not violate any consensus rules that concern the
    /// block's layout (hash, versioned hashes, fork-gated fields), mirroring the Ethereum
    /// validator for the Seismic block type.
    pub fn ensure_well_formed_payload(
        &self,
        payload: SeismicExecutionData,
    ) -> Result<SealedBlock<SeismicBlock>, PayloadError> {
        let expected_hash = payload.payload.block_hash();
        let sidecar = payload.sidecar.clone();

        // First parse the block
        let sealed_block = payload.try_into_block()?.seal_slow();

        // Ensure the hash included in the payload matches the block hash
        if expected_hash != sealed_block.hash() {
            return Err(PayloadError::BlockHash {
                execution: sealed_block.hash(),
                consensus: expected_hash,
            })
        }

        let timestamp = sealed_block.timestamp();
        shanghai::ensure_well_formed_fields(
            sealed_block.body(),
            self.chain_spec.is_shanghai_active_at_timestamp(timestamp),
        )?;
        cancun::ensure_well_formed_fields(
            &sealed_block,
            sidecar.cancun(),
            self.chain_spec.is_cancun_active_at_timestamp(timestamp),
        )?;
        prague::ensure_well_formed_fields(
            sealed_block.body(),
            sidecar.prague(),
            self.chain_spec.is_prague_active_at_timestamp(timestamp),
        )?;

        Ok(sealed_block)
    }
}

impl PayloadValidator<SeismicEngineTypes> for SeismicEngineValidator {
    type Block = SeismicBlock;

    fn ensure_well_formed_payload(
        &self,
        payload: SeismicExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block = Self::ensure_well_formed_payload(self, payload)?;
        sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }

    /// The Engine API rule "attributes.timestamp > head.timestamp" is applied in milliseconds:
    /// Seismic builds several blocks per second, so a build request may share the head's seconds
    /// `timestamp` as long as its millisecond block time is strictly later (the same ordering
    /// `SeismicConsensus` enforces on the resulting header).
    fn validate_payload_attributes_against_header(
        &self,
        attr: &SeismicPayloadAttributes,
        header: &SeismicHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        if !reth_seismic_engine_primitives::is_valid_millis_part(attr.timestamp_millis_part) ||
            attr.timestamp_millis() <= header.timestamp_millis()
        {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

impl<Types> EngineApiValidator<Types> for SeismicEngineValidator
where
    Types: PayloadTypes<
        PayloadAttributes = SeismicPayloadAttributes,
        ExecutionData = SeismicExecutionData,
    >,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, SeismicExecutionData, SeismicPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        if let PayloadOrAttributes::ExecutionPayload(payload) = &payload_or_attrs {
            if let Some(requests) = payload.sidecar.requests() {
                validate_execution_requests(requests)?;
            }
        }

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &SeismicPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        if !reth_seismic_engine_primitives::is_valid_millis_part(attributes.timestamp_millis_part) {
            return Err(EngineObjectValidationError::invalid_params(
                reth_seismic_engine_primitives::SeismicPayloadAttributesError::InvalidMillisPart(
                    attributes.timestamp_millis_part,
                ),
            ))
        }
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<SeismicExecutionData, SeismicPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

/// The authenticated `engine_` namespace served to the Seismic consensus client.
///
/// Payload attributes and execution payloads are the Seismic extensions of the stock types
/// (they carry `timestampMillisPart`); everything else matches the Ethereum Engine API.
#[rpc(server, namespace = "engine", server_bounds(Engine::PayloadAttributes: jsonrpsee::core::DeserializeOwned))]
pub trait SeismicEngineApi<Engine: EngineTypes> {
    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_newpayloadv3>
    #[method(name = "newPayloadV3")]
    async fn new_payload_v3(
        &self,
        payload: SeismicExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
    ) -> RpcResult<PayloadStatus>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/prague.md#engine_newpayloadv4>
    #[method(name = "newPayloadV4")]
    async fn new_payload_v4(
        &self,
        payload: SeismicExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        execution_requests: Requests,
    ) -> RpcResult<PayloadStatus>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_forkchoiceupdatedv3>
    #[method(name = "forkchoiceUpdatedV3")]
    async fn fork_choice_updated_v3(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<Engine::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_getpayloadv3>
    #[method(name = "getPayloadV3")]
    async fn get_payload_v3(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<Engine::ExecutionPayloadEnvelopeV3>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/prague.md#engine_getpayloadv4>
    #[method(name = "getPayloadV4")]
    async fn get_payload_v4(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<Engine::ExecutionPayloadEnvelopeV4>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_getpayloadbodiesbyhashv1>
    #[method(name = "getPayloadBodiesByHashV1")]
    async fn get_payload_bodies_by_hash_v1(
        &self,
        block_hashes: Vec<BlockHash>,
    ) -> RpcResult<ExecutionPayloadBodiesV1>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_getpayloadbodiesbyrangev1>
    #[method(name = "getPayloadBodiesByRangeV1")]
    async fn get_payload_bodies_by_range_v1(
        &self,
        start: U64,
        count: U64,
    ) -> RpcResult<ExecutionPayloadBodiesV1>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/identification.md#engine_getclientversionv1>
    #[method(name = "getClientVersionV1")]
    async fn get_client_version_v1(
        &self,
        client_version: ClientVersionV1,
    ) -> RpcResult<Vec<ClientVersionV1>>;

    /// See also <https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#capabilities>
    #[method(name = "exchangeCapabilities")]
    async fn exchange_capabilities(&self, capabilities: Vec<String>) -> RpcResult<Vec<String>>;
}

/// The Seismic Engine API implementation: a thin wrapper around reth's [`EngineApi`] that maps
/// the Seismic payload types onto the generic handlers.
#[derive(Debug)]
pub struct SeismicEngineApi<Provider, EngineT: EngineTypes, Pool, Validator, ChainSpec> {
    inner: EngineApi<Provider, EngineT, Pool, Validator, ChainSpec>,
}

impl<Provider, EngineT: EngineTypes, Pool, Validator, ChainSpec>
    SeismicEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>
{
    /// Wraps the given generic engine API.
    pub const fn new(inner: EngineApi<Provider, EngineT, Pool, Validator, ChainSpec>) -> Self {
        Self { inner }
    }
}

impl<Provider, EngineT: EngineTypes, Pool, Validator, ChainSpec> Clone
    for SeismicEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>
{
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

#[async_trait::async_trait]
impl<Provider, EngineT, Pool, Validator, ChainSpec> SeismicEngineApiServer<EngineT>
    for SeismicEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>
where
    Provider: HeaderProvider + BlockReader + StateProviderFactory + 'static,
    EngineT: EngineTypes<ExecutionData = SeismicExecutionData>,
    Pool: TransactionPool + 'static,
    Validator: EngineApiValidator<EngineT>,
    ChainSpec: EthereumHardforks + Send + Sync + 'static,
{
    async fn new_payload_v3(
        &self,
        payload: SeismicExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
    ) -> RpcResult<PayloadStatus> {
        trace!(target: "rpc::engine", "Serving engine_newPayloadV3");
        let payload = SeismicExecutionData::v3(
            payload,
            CancunPayloadFields { versioned_hashes, parent_beacon_block_root },
        );
        Ok(self.inner.new_payload_v3_metered(payload).await?)
    }

    async fn new_payload_v4(
        &self,
        payload: SeismicExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        execution_requests: Requests,
    ) -> RpcResult<PayloadStatus> {
        trace!(target: "rpc::engine", "Serving engine_newPayloadV4");
        let payload = SeismicExecutionData::v4(
            payload,
            CancunPayloadFields { versioned_hashes, parent_beacon_block_root },
            PraguePayloadFields { requests: RequestsOrHash::Requests(execution_requests) },
        );
        Ok(self.inner.new_payload_v4_metered(payload).await?)
    }

    async fn fork_choice_updated_v3(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        trace!(target: "rpc::engine", "Serving engine_forkchoiceUpdatedV3");
        Ok(self.inner.fork_choice_updated_v3_metered(fork_choice_state, payload_attributes).await?)
    }

    async fn get_payload_v3(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<EngineT::ExecutionPayloadEnvelopeV3> {
        trace!(target: "rpc::engine", "Serving engine_getPayloadV3");
        Ok(self.inner.get_payload_v3_metered(payload_id).await?)
    }

    async fn get_payload_v4(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<EngineT::ExecutionPayloadEnvelopeV4> {
        trace!(target: "rpc::engine", "Serving engine_getPayloadV4");
        Ok(self.inner.get_payload_v4_metered(payload_id).await?)
    }

    async fn get_payload_bodies_by_hash_v1(
        &self,
        block_hashes: Vec<BlockHash>,
    ) -> RpcResult<ExecutionPayloadBodiesV1> {
        trace!(target: "rpc::engine", "Serving engine_getPayloadBodiesByHashV1");
        Ok(self.inner.get_payload_bodies_by_hash_v1_metered(block_hashes).await?)
    }

    async fn get_payload_bodies_by_range_v1(
        &self,
        start: U64,
        count: U64,
    ) -> RpcResult<ExecutionPayloadBodiesV1> {
        trace!(target: "rpc::engine", "Serving engine_getPayloadBodiesByRangeV1");
        Ok(self.inner.get_payload_bodies_by_range_v1_metered(start.to(), count.to()).await?)
    }

    async fn get_client_version_v1(
        &self,
        client: ClientVersionV1,
    ) -> RpcResult<Vec<ClientVersionV1>> {
        trace!(target: "rpc::engine", "Serving engine_getClientVersionV1");
        Ok(self.inner.get_client_version_v1(client)?)
    }

    async fn exchange_capabilities(&self, _capabilities: Vec<String>) -> RpcResult<Vec<String>> {
        Ok(self.inner.capabilities().list())
    }
}

impl<Provider, EngineT, Pool, Validator, ChainSpec> IntoEngineApiRpcModule
    for SeismicEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>
where
    EngineT: EngineTypes,
    Self: SeismicEngineApiServer<EngineT>,
{
    fn into_rpc_module(self) -> RpcModule<()> {
        self.into_rpc().remove_context()
    }
}

/// Builder for the Seismic [`SeismicEngineApi`].
#[derive(Debug, Default, Clone)]
pub struct SeismicEngineApiBuilder<EV> {
    engine_validator_builder: EV,
}

impl<N, EV> reth_node_builder::rpc::EngineApiBuilder<N> for SeismicEngineApiBuilder<EV>
where
    N: reth_node_api::FullNodeComponents<
        Types: reth_node_api::NodeTypes<
            ChainSpec: EthereumHardforks,
            Payload: EngineTypes<ExecutionData = SeismicExecutionData>,
        >,
    >,
    EV: reth_node_builder::rpc::PayloadValidatorBuilder<N>,
    EV::Validator: EngineApiValidator<<N::Types as reth_node_api::NodeTypes>::Payload>,
{
    type EngineApi = SeismicEngineApi<
        N::Provider,
        <N::Types as reth_node_api::NodeTypes>::Payload,
        N::Pool,
        EV::Validator,
        <N::Types as reth_node_api::NodeTypes>::ChainSpec,
    >;

    async fn build_engine_api(
        self,
        ctx: &reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::EngineApi> {
        use reth_node_core::version::{version_metadata, CLIENT_CODE};

        let Self { engine_validator_builder } = self;

        let engine_validator = engine_validator_builder.build(ctx).await?;
        let client = ClientVersionV1 {
            code: CLIENT_CODE,
            name: version_metadata().name_client.to_string(),
            version: version_metadata().cargo_pkg_version.to_string(),
            commit: version_metadata().vergen_git_sha.to_string(),
        };
        let inner = EngineApi::new(
            ctx.node.provider().clone(),
            ctx.config.chain.clone(),
            ctx.beacon_engine_handle.clone(),
            reth_payload_builder::PayloadStore::new(ctx.node.payload_builder_handle().clone()),
            ctx.node.pool().clone(),
            Box::new(ctx.node.task_executor().clone()),
            client,
            reth_rpc_engine_api::EngineCapabilities::new(
                SEISMIC_ENGINE_CAPABILITIES.iter().copied(),
            ),
            engine_validator,
            ctx.config.engine.accept_execution_requests_hash,
        );

        Ok(SeismicEngineApi::new(inner))
    }
}
