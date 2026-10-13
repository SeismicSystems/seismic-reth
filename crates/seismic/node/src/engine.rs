//! Seismic engine API types and validators.
//!
//! Seismic blocks are stock Ethereum blocks (the sub-second timestamp component lives in the
//! header's `extraData`), so execution payloads and `engine_getPayload` envelopes are the stock
//! Engine API types. Only `engine_forkchoiceUpdated` payload attributes are extended, with an
//! explicit `timestampMillisPart` (see [`reth_seismic_engine_primitives`]).

use alloy_consensus::Header;
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3,
    ExecutionPayloadEnvelopeV4, ExecutionPayloadEnvelopeV5, ExecutionPayloadV1,
};
use reth_chainspec::ChainSpec;
use reth_engine_primitives::{EngineTypes, PayloadValidator};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_node_api::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineApiValidator, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_payload_primitives::{InvalidPayloadAttributesError, PayloadTypes};
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_seismic_engine_primitives::{
    execution_data_from_sealed_block, is_valid_millis_part, SeismicBuiltPayload,
    SeismicPayloadAttributes, SeismicPayloadAttributesError, SeismicPayloadBuilderAttributes,
};
use reth_seismic_primitives::{SeismicBlock, SeismicBlockHeader};
use std::sync::Arc;

/// The types used by the Seismic beacon consensus engine.
#[derive(Debug, Default, Clone, Copy, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct SeismicEngineTypes;

impl PayloadTypes for SeismicEngineTypes {
    type ExecutionData = ExecutionData;
    type BuiltPayload = SeismicBuiltPayload;
    type PayloadAttributes = SeismicPayloadAttributes;
    type PayloadBuilderAttributes = SeismicPayloadBuilderAttributes;

    fn block_to_payload(block: SealedBlock<SeismicBlock>) -> Self::ExecutionData {
        execution_data_from_sealed_block(block)
    }
}

impl EngineTypes for SeismicEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
}

/// Validator for the Seismic engine API.
#[derive(Debug, Clone)]
pub struct SeismicEngineValidator {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl SeismicEngineValidator {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthereumExecutionPayloadValidator::new(chain_spec) }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl PayloadValidator<SeismicEngineTypes> for SeismicEngineValidator {
    type Block = SeismicBlock;

    /// Ensures that the given payload does not violate any consensus rules that concern the
    /// block's layout (hash, versioned hashes, fork-gated fields). The Seismic `extraData`
    /// layout is enforced by consensus when the block is validated against the chain.
    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block: SealedBlock<SeismicBlock> =
            self.inner.ensure_well_formed_payload(payload)?;
        sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }

    /// The Engine API rule "attributes.timestamp > head.timestamp" is applied in milliseconds:
    /// Seismic builds several blocks per second, so a build request may share the head's seconds
    /// `timestamp` as long as its millisecond block time is strictly later (the same ordering
    /// `SeismicConsensus` enforces on the resulting header).
    fn validate_payload_attributes_against_header(
        &self,
        attr: &SeismicPayloadAttributes,
        header: &Header,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // A canonical head always carries the `extraData` prefix (consensus checked it, and the
        // genesis templates ship it); a malformed one is treated as a zero component.
        if !is_valid_millis_part(attr.timestamp_millis_part) ||
            attr.timestamp_millis() <= header.timestamp_millis()
        {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

impl<Types> EngineApiValidator<Types> for SeismicEngineValidator
where
    Types:
        PayloadTypes<PayloadAttributes = SeismicPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, ExecutionData, SeismicPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &SeismicPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        if !is_valid_millis_part(attributes.timestamp_millis_part) {
            return Err(EngineObjectValidationError::invalid_params(
                SeismicPayloadAttributesError::InvalidMillisPart(attributes.timestamp_millis_part),
            ))
        }
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<ExecutionData, SeismicPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}
