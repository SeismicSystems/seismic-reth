//! Execution payloads for `engine_newPayload` / `engine_getPayload`.

use crate::{join_timestamp_millis, split_timestamp_millis};
use alloy_eips::eip7685::Requests;
use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{BlobsBundleV1, ExecutionPayloadV3};
use serde::{Deserialize, Serialize};

/// Seismic execution payload: the stock [`ExecutionPayloadV3`] plus the sub-second component of
/// the block timestamp.
///
/// `inner.timestamp` is in Unix seconds and `inner.block_hash` is the hash of the full Seismic
/// header (which commits to `timestamp_millis_part`), so the hash of the embedded stock fields
/// alone does **not** equal `block_hash`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ssz", derive(ssz_derive::Encode, ssz_derive::Decode))]
pub struct SeismicExecutionPayloadV3 {
    /// The stock Cancun execution payload. `timestamp` is in Unix seconds.
    #[deref]
    #[deref_mut]
    #[serde(flatten)]
    pub inner: ExecutionPayloadV3,
    /// Sub-second (milliseconds) component of the block timestamp, `0..1000`.
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp_millis_part: u64,
}

impl SeismicExecutionPayloadV3 {
    /// Wraps a stock payload with an explicit sub-second component.
    pub const fn new(inner: ExecutionPayloadV3, timestamp_millis_part: u64) -> Self {
        Self { inner, timestamp_millis_part }
    }

    /// Builds a payload from a Unix millisecond block time, splitting it into the stock seconds
    /// `timestamp` and the sub-second component.
    pub const fn from_timestamp_millis(
        mut inner: ExecutionPayloadV3,
        timestamp_millis: u64,
    ) -> Self {
        let (timestamp, timestamp_millis_part) = split_timestamp_millis(timestamp_millis);
        inner.payload_inner.payload_inner.timestamp = timestamp;
        Self { inner, timestamp_millis_part }
    }

    /// Returns the block hash committed to by this payload.
    pub const fn block_hash(&self) -> B256 {
        self.inner.payload_inner.payload_inner.block_hash
    }

    /// Returns the parent block hash.
    pub const fn parent_hash(&self) -> B256 {
        self.inner.payload_inner.payload_inner.parent_hash
    }

    /// Returns the block number.
    pub const fn block_number(&self) -> u64 {
        self.inner.payload_inner.payload_inner.block_number
    }

    /// Returns the block time in Unix seconds.
    pub const fn timestamp(&self) -> u64 {
        self.inner.payload_inner.payload_inner.timestamp
    }

    /// Returns the block time in Unix milliseconds.
    pub const fn timestamp_millis(&self) -> u64 {
        join_timestamp_millis(self.timestamp(), self.timestamp_millis_part)
    }

    /// Returns the gas used by the block.
    pub const fn gas_used(&self) -> u64 {
        self.inner.payload_inner.payload_inner.gas_used
    }
}

/// Response of `engine_getPayloadV3`, with a [`SeismicExecutionPayloadV3`] in place of the stock
/// payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeismicExecutionPayloadEnvelopeV3 {
    /// Execution payload V3
    pub execution_payload: SeismicExecutionPayloadV3,
    /// The expected value to be received by the feeRecipient in wei
    pub block_value: U256,
    /// The blobs, commitments, and proofs associated with the executed payload.
    pub blobs_bundle: BlobsBundleV1,
    /// Introduced in V3, this represents a suggestion from the execution layer if the payload
    /// should be used instead of an externally provided one.
    pub should_override_builder: bool,
}

/// Response of `engine_getPayloadV4`, with a [`SeismicExecutionPayloadV3`] in place of the stock
/// payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, derive_more::Deref)]
#[serde(rename_all = "camelCase")]
pub struct SeismicExecutionPayloadEnvelopeV4 {
    /// The inner V3 envelope.
    #[deref]
    #[serde(flatten)]
    pub envelope_inner: SeismicExecutionPayloadEnvelopeV3,
    /// A list of opaque [EIP-7685][eip7685] requests.
    ///
    /// [eip7685]: https://eips.ethereum.org/EIPS/eip-7685
    pub execution_requests: Requests,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2};

    fn payload() -> SeismicExecutionPayloadV3 {
        SeismicExecutionPayloadV3::from_timestamp_millis(
            ExecutionPayloadV3 {
                payload_inner: ExecutionPayloadV2 {
                    payload_inner: ExecutionPayloadV1 {
                        parent_hash: B256::repeat_byte(0xbb),
                        fee_recipient: Default::default(),
                        state_root: Default::default(),
                        receipts_root: Default::default(),
                        logs_bloom: Default::default(),
                        prev_randao: Default::default(),
                        block_number: 7,
                        gas_limit: 0,
                        gas_used: 0,
                        timestamp: 0,
                        extra_data: Default::default(),
                        base_fee_per_gas: U256::ZERO,
                        block_hash: B256::repeat_byte(0xaa),
                        transactions: vec![],
                    },
                    withdrawals: vec![],
                },
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            1_700_000_000_123,
        )
    }

    #[test]
    fn accessors() {
        let payload = payload();
        assert_eq!(payload.timestamp(), 1_700_000_000);
        assert_eq!(payload.timestamp_millis_part, 123);
        assert_eq!(payload.timestamp_millis(), 1_700_000_000_123);
        assert_eq!(payload.block_number(), 7);
        assert_eq!(payload.block_hash(), B256::repeat_byte(0xaa));
        assert_eq!(payload.parent_hash(), B256::repeat_byte(0xbb));
    }

    #[test]
    fn json_is_flat_and_roundtrips() {
        let value = serde_json::to_value(payload()).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object["timestamp"], "0x6553f100");
        assert_eq!(object["timestampMillisPart"], "0x7b");
        assert_eq!(object["blockNumber"], "0x7");
        let decoded: SeismicExecutionPayloadV3 = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, payload());

        let envelope = SeismicExecutionPayloadEnvelopeV4 {
            envelope_inner: SeismicExecutionPayloadEnvelopeV3 {
                execution_payload: payload(),
                block_value: U256::from(5),
                blobs_bundle: BlobsBundleV1::empty(),
                should_override_builder: false,
            },
            execution_requests: Requests::default(),
        };
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["executionPayload"]["timestampMillisPart"], "0x7b");
        assert_eq!(value["blockValue"], "0x5");
        let decoded: SeismicExecutionPayloadEnvelopeV4 = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn ssz_roundtrips() {
        use ssz::{Decode, Encode};
        let payload = payload();
        let bytes = payload.as_ssz_bytes();
        assert_eq!(SeismicExecutionPayloadV3::from_ssz_bytes(&bytes).unwrap(), payload);
    }
}
