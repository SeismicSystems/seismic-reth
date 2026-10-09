//! Reth-side Engine API primitives for Seismic: payload attributes, execution data, built
//! payloads, builder attributes and block ⇄ payload conversions.
//!
//! The wire types themselves live in [`reth_seismic_engine_types`], which stays free of reth
//! dependencies so the consensus client can share it. This crate wraps them with the reth trait
//! implementations the node needs.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::{Block, BlockBody};
use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
    eip7685::Requests,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::{
    BlobsBundleV1, CancunPayloadFields, ExecutionPayload, ExecutionPayloadSidecar,
    ExecutionPayloadV3, PayloadAttributes, PayloadError, PayloadId, PraguePayloadFields,
};
use reth_ethereum_engine_primitives::{payload_id, BlobSidecars, BuiltPayloadConversionError};
use reth_payload_primitives::{BuiltPayload, PayloadBuilderAttributes};
use reth_primitives_traits::SealedBlock;
pub use reth_seismic_engine_types::{
    is_valid_millis_part, join_timestamp_millis, split_timestamp_millis,
    SeismicExecutionPayloadEnvelopeV3, SeismicExecutionPayloadEnvelopeV4,
    SeismicExecutionPayloadV3, MILLIS_PER_SECOND,
};
use reth_seismic_primitives::{SeismicBlock, SeismicHeader, SeismicPrimitives};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// `engine_forkchoiceUpdated` payload attributes as accepted by the Seismic node.
///
/// A transparent wrapper around the shared wire type
/// [`reth_seismic_engine_types::SeismicPayloadAttributes`] (identical JSON) that carries the reth
/// trait implementations.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut,
)]
#[serde(transparent)]
pub struct SeismicPayloadAttributes(pub reth_seismic_engine_types::SeismicPayloadAttributes);

impl SeismicPayloadAttributes {
    /// Wraps stock attributes with an explicit sub-second component.
    pub const fn new(inner: PayloadAttributes, timestamp_millis_part: u64) -> Self {
        Self(reth_seismic_engine_types::SeismicPayloadAttributes::new(inner, timestamp_millis_part))
    }

    /// Builds attributes from a Unix millisecond block time.
    pub const fn from_timestamp_millis(inner: PayloadAttributes, timestamp_millis: u64) -> Self {
        Self(reth_seismic_engine_types::SeismicPayloadAttributes::from_timestamp_millis(
            inner,
            timestamp_millis,
        ))
    }
}

impl From<PayloadAttributes> for SeismicPayloadAttributes {
    /// Wraps stock attributes with a zero sub-second component.
    fn from(inner: PayloadAttributes) -> Self {
        Self::new(inner, 0)
    }
}

impl From<reth_seismic_engine_types::SeismicPayloadAttributes> for SeismicPayloadAttributes {
    fn from(inner: reth_seismic_engine_types::SeismicPayloadAttributes) -> Self {
        Self(inner)
    }
}

/// A [`SeismicExecutionPayloadV3`] together with the out-of-band `engine_newPayload` fields
/// (versioned hashes, parent beacon block root, execution requests).
///
/// This is the Seismic counterpart of [`alloy_rpc_types_engine::ExecutionData`]. Seismic chains
/// are post-Cancun from genesis, so only V3 payloads are representable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeismicExecutionData {
    /// The execution payload.
    pub payload: SeismicExecutionPayloadV3,
    /// The additional `engine_newPayload` fields.
    pub sidecar: ExecutionPayloadSidecar,
}

impl SeismicExecutionData {
    /// Creates the execution data for an `engine_newPayloadV3` request.
    pub fn v3(payload: SeismicExecutionPayloadV3, cancun: CancunPayloadFields) -> Self {
        Self { payload, sidecar: ExecutionPayloadSidecar::v3(cancun) }
    }

    /// Creates the execution data for an `engine_newPayloadV4` request.
    pub fn v4(
        payload: SeismicExecutionPayloadV3,
        cancun: CancunPayloadFields,
        prague: PraguePayloadFields,
    ) -> Self {
        Self { payload, sidecar: ExecutionPayloadSidecar::v4(cancun, prague) }
    }

    /// Returns the block time in Unix milliseconds.
    pub const fn timestamp_millis(&self) -> u64 {
        self.payload.timestamp_millis()
    }
}

impl reth_payload_primitives::PayloadAttributes for SeismicPayloadAttributes {
    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals.as_ref()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }
}

impl reth_payload_primitives::ExecutionPayload for SeismicExecutionData {
    fn parent_hash(&self) -> B256 {
        self.payload.parent_hash()
    }

    fn block_hash(&self) -> B256 {
        self.payload.block_hash()
    }

    fn block_number(&self) -> u64 {
        self.payload.block_number()
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        Some(&self.payload.inner.payload_inner.withdrawals)
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.sidecar.parent_beacon_block_root()
    }

    fn timestamp(&self) -> u64 {
        self.payload.timestamp()
    }

    fn gas_used(&self) -> u64 {
        self.payload.gas_used()
    }
}

/// Error returned when a [`SeismicPayloadAttributes`] cannot be turned into builder attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SeismicPayloadAttributesError {
    /// `timestampMillisPart` is not in `0..1000`.
    #[error("timestampMillisPart {0} is out of range (expected 0..1000)")]
    InvalidMillisPart(u64),
}

/// Attributes the Seismic payload builder works from: the stock Ethereum builder attributes plus
/// the sub-second component of the block timestamp.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
pub struct SeismicPayloadBuilderAttributes {
    /// The stock builder attributes. `timestamp` is in Unix seconds.
    #[deref]
    pub inner: reth_ethereum_engine_primitives::EthPayloadBuilderAttributes,
    /// Sub-second (milliseconds) component of the block timestamp, `0..1000`.
    pub timestamp_millis_part: u64,
}

impl SeismicPayloadBuilderAttributes {
    /// Derives builder attributes (including the unique [`PayloadId`]) for the given parent and
    /// attributes.
    ///
    /// The payload id commits to the sub-second component so two builds that differ only in
    /// `timestampMillisPart` get distinct ids.
    pub fn new(
        parent: B256,
        attributes: SeismicPayloadAttributes,
    ) -> Result<Self, SeismicPayloadAttributesError> {
        if !is_valid_millis_part(attributes.timestamp_millis_part) {
            return Err(SeismicPayloadAttributesError::InvalidMillisPart(
                attributes.timestamp_millis_part,
            ))
        }
        let mut inner = reth_ethereum_engine_primitives::EthPayloadBuilderAttributes::new(
            parent,
            attributes.0.inner.clone(),
        );
        inner.id = seismic_payload_id(&parent, &attributes);
        Ok(Self { inner, timestamp_millis_part: attributes.timestamp_millis_part })
    }

    /// Returns the block time in Unix milliseconds.
    pub const fn timestamp_millis(&self) -> u64 {
        join_timestamp_millis(self.inner.timestamp, self.timestamp_millis_part)
    }
}

/// Generates the payload id for the given parent and Seismic attributes.
///
/// This is the stock Ethereum payload id hashed together with `timestampMillisPart`, so ids for
/// attributes with a zero sub-second component differ from the stock id of the same inner
/// attributes.
pub fn seismic_payload_id(parent: &B256, attributes: &SeismicPayloadAttributes) -> PayloadId {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(payload_id(parent, &attributes.0.inner).0.as_slice());
    hasher.update(attributes.timestamp_millis_part.to_be_bytes());
    let out: [u8; 32] = hasher.finalize().into();
    let mut id = [0u8; 8];
    id.copy_from_slice(out.split_at(8).0);
    PayloadId::new(id)
}

impl From<reth_ethereum_engine_primitives::EthPayloadBuilderAttributes>
    for SeismicPayloadBuilderAttributes
{
    /// Wraps stock builder attributes with a zero sub-second component. The payload id is kept
    /// as derived by the stock attributes.
    fn from(inner: reth_ethereum_engine_primitives::EthPayloadBuilderAttributes) -> Self {
        Self { inner, timestamp_millis_part: 0 }
    }
}

/// Local (dev-mode) payload attributes: the stock builder's attributes with a zero sub-second
/// component, since the local miner ticks in whole seconds.
impl<ChainSpec> reth_payload_primitives::PayloadAttributesBuilder<SeismicPayloadAttributes>
    for reth_engine_local::LocalPayloadAttributesBuilder<ChainSpec>
where
    Self: reth_payload_primitives::PayloadAttributesBuilder<
        alloy_rpc_types_engine::PayloadAttributes,
    >,
{
    fn build(&self, timestamp: u64) -> SeismicPayloadAttributes {
        SeismicPayloadAttributes::from(reth_payload_primitives::PayloadAttributesBuilder::<
            alloy_rpc_types_engine::PayloadAttributes,
        >::build(self, timestamp))
    }
}

impl PayloadBuilderAttributes for SeismicPayloadBuilderAttributes {
    type RpcPayloadAttributes = SeismicPayloadAttributes;
    type Error = SeismicPayloadAttributesError;

    fn try_new(
        parent: B256,
        attributes: SeismicPayloadAttributes,
        _version: u8,
    ) -> Result<Self, Self::Error> {
        Self::new(parent, attributes)
    }

    fn payload_id(&self) -> PayloadId {
        self.inner.id
    }

    fn parent(&self) -> B256 {
        self.inner.parent
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }

    fn suggested_fee_recipient(&self) -> Address {
        self.inner.suggested_fee_recipient
    }

    fn prev_randao(&self) -> B256 {
        self.inner.prev_randao
    }

    fn withdrawals(&self) -> &Withdrawals {
        &self.inner.withdrawals
    }
}

/// A Seismic payload built by the payload builder.
#[derive(Debug, Clone)]
pub struct SeismicBuiltPayload {
    /// Identifier of the payload
    pub id: PayloadId,
    /// The built block
    pub block: Arc<SealedBlock<SeismicBlock>>,
    /// The fees of the block
    pub fees: U256,
    /// The blobs, proofs, and commitments in the block.
    pub sidecars: BlobSidecars,
    /// The requests of the payload
    pub requests: Option<Requests>,
}

impl SeismicBuiltPayload {
    /// Creates a new built payload.
    pub const fn new(
        id: PayloadId,
        block: Arc<SealedBlock<SeismicBlock>>,
        fees: U256,
        sidecars: BlobSidecars,
        requests: Option<Requests>,
    ) -> Self {
        Self { id, block, fees, sidecars, requests }
    }

    /// Returns the identifier of the payload.
    pub const fn id(&self) -> PayloadId {
        self.id
    }

    /// Returns the built block (sealed).
    pub fn block(&self) -> &SealedBlock<SeismicBlock> {
        &self.block
    }

    /// Fees of the block
    pub const fn fees(&self) -> U256 {
        self.fees
    }

    /// Converts the built payload into a `engine_getPayloadV3` response.
    pub fn try_into_v3(
        self,
    ) -> Result<SeismicExecutionPayloadEnvelopeV3, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, .. } = self;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV1::empty(),
            BlobSidecars::Eip4844(sidecars) => BlobsBundleV1::from(sidecars),
            BlobSidecars::Eip7594(_) => {
                return Err(BuiltPayloadConversionError::UnexpectedEip7594Sidecars)
            }
        };
        Ok(SeismicExecutionPayloadEnvelopeV3 {
            execution_payload: execution_payload_from_sealed_block(Arc::unwrap_or_clone(block)),
            block_value: fees,
            // Spec: clients without an override heuristic SHOULD set this to `false`.
            should_override_builder: false,
            blobs_bundle,
        })
    }

    /// Converts the built payload into a `engine_getPayloadV4` response.
    pub fn try_into_v4(
        self,
    ) -> Result<SeismicExecutionPayloadEnvelopeV4, BuiltPayloadConversionError> {
        let execution_requests = self.requests.clone().unwrap_or_default();
        Ok(SeismicExecutionPayloadEnvelopeV4 {
            envelope_inner: self.try_into_v3()?,
            execution_requests,
        })
    }
}

impl BuiltPayload for SeismicBuiltPayload {
    type Primitives = SeismicPrimitives;

    fn block(&self) -> &SealedBlock<SeismicBlock> {
        &self.block
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

/// Error returned when a Seismic payload is requested through an Engine API version that
/// cannot represent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("engine API {0} cannot carry Seismic payloads; use V3 or V4")]
pub struct UnsupportedEngineVersion(pub &'static str);

impl TryFrom<SeismicBuiltPayload> for alloy_rpc_types_engine::ExecutionPayloadV1 {
    type Error = UnsupportedEngineVersion;

    fn try_from(_: SeismicBuiltPayload) -> Result<Self, Self::Error> {
        Err(UnsupportedEngineVersion("getPayloadV1"))
    }
}

impl TryFrom<SeismicBuiltPayload> for alloy_rpc_types_engine::ExecutionPayloadEnvelopeV2 {
    type Error = UnsupportedEngineVersion;

    fn try_from(_: SeismicBuiltPayload) -> Result<Self, Self::Error> {
        Err(UnsupportedEngineVersion("getPayloadV2"))
    }
}

impl TryFrom<SeismicBuiltPayload> for alloy_rpc_types_engine::ExecutionPayloadEnvelopeV5 {
    type Error = UnsupportedEngineVersion;

    fn try_from(_: SeismicBuiltPayload) -> Result<Self, Self::Error> {
        Err(UnsupportedEngineVersion("getPayloadV5"))
    }
}

impl TryFrom<SeismicBuiltPayload> for SeismicExecutionPayloadEnvelopeV3 {
    type Error = BuiltPayloadConversionError;

    fn try_from(value: SeismicBuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v3()
    }
}

impl TryFrom<SeismicBuiltPayload> for SeismicExecutionPayloadEnvelopeV4 {
    type Error = BuiltPayloadConversionError;

    fn try_from(value: SeismicBuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v4()
    }
}

/// Converts a sealed Seismic block into an execution payload without re-validating the hash.
pub fn execution_payload_from_sealed_block(
    block: SealedBlock<SeismicBlock>,
) -> SeismicExecutionPayloadV3 {
    let hash = block.hash();
    let block = block.into_block();
    SeismicExecutionPayloadV3::new(
        ExecutionPayloadV3::from_block_unchecked(hash, &block),
        block.header.timestamp_millis_part,
    )
}

impl SeismicExecutionData {
    /// Converts a sealed Seismic block into the execution data `engine_newPayloadV4` would carry.
    pub fn from_sealed_block(block: SealedBlock<SeismicBlock>) -> Self {
        let hash = block.hash();
        let block = block.into_block();
        let sidecar = ExecutionPayloadSidecar::from_block(&block);
        Self {
            payload: SeismicExecutionPayloadV3::new(
                ExecutionPayloadV3::from_block_unchecked(hash, &block),
                block.header.timestamp_millis_part,
            ),
            sidecar,
        }
    }

    /// Converts the execution data into a Seismic block.
    ///
    /// This performs the stock Ethereum payload → block conversion and attaches the sub-second
    /// timestamp component. The result's hash is not checked against the payload's `blockHash`.
    pub fn try_into_block(self) -> Result<SeismicBlock, PayloadError> {
        let Self { payload, sidecar } = self;
        let SeismicExecutionPayloadV3 { inner, timestamp_millis_part } = payload;
        if !is_valid_millis_part(timestamp_millis_part) {
            return Err(PayloadError::Decode(alloy_rlp::Error::Custom(
                "timestampMillisPart out of range",
            )))
        }
        let Block { header, body } =
            ExecutionPayload::V3(inner).try_into_block_with_sidecar(&sidecar)?;
        let BlockBody { transactions, ommers, withdrawals } = body;
        // Post-merge blocks carry no ommers; map the (empty) list for type parity.
        let ommers = ommers.into_iter().map(SeismicHeader::from).collect();
        Ok(Block::new(
            SeismicHeader::new(header, timestamp_millis_part),
            BlockBody { transactions, ommers, withdrawals },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_rpc_types_engine::PayloadAttributes;

    fn attrs(part: u64) -> SeismicPayloadAttributes {
        SeismicPayloadAttributes::new(
            PayloadAttributes {
                timestamp: 1_700_000_000,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::ZERO),
            },
            part,
        )
    }

    #[test]
    fn builder_attributes_commit_to_millis_part() {
        let a = SeismicPayloadBuilderAttributes::new(B256::ZERO, attrs(1)).unwrap();
        let b = SeismicPayloadBuilderAttributes::new(B256::ZERO, attrs(2)).unwrap();
        assert_ne!(a.payload_id(), b.payload_id());
        assert_ne!(a.payload_id(), payload_id(&B256::ZERO, &attrs(1).inner));
        assert_eq!(a.timestamp_millis(), 1_700_000_000_001);
        assert_eq!(
            SeismicPayloadBuilderAttributes::new(B256::ZERO, attrs(1000)),
            Err(SeismicPayloadAttributesError::InvalidMillisPart(1000))
        );
    }

    #[test]
    fn block_payload_roundtrip() {
        let header = SeismicHeader::new(
            Header {
                number: 3,
                timestamp: 1_700_000_000,
                base_fee_per_gas: Some(7),
                withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::ZERO),
                requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
                ..Default::default()
            },
            456,
        );
        let block = SeismicBlock::new(
            header,
            alloy_consensus::BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(Withdrawals::default()),
            },
        );
        let sealed = SealedBlock::seal_slow(block.clone());
        let data = SeismicExecutionData::from_sealed_block(sealed.clone());
        assert_eq!(data.payload.block_hash(), sealed.hash());
        assert_eq!(data.payload.timestamp(), 1_700_000_000);
        assert_eq!(data.payload.timestamp_millis_part, 456);
        assert_eq!(data.sidecar.parent_beacon_block_root(), Some(B256::ZERO));

        let decoded = data.try_into_block().unwrap();
        assert_eq!(decoded, block);
        assert_eq!(SealedBlock::seal_slow(decoded).hash(), sealed.hash());
    }
}
