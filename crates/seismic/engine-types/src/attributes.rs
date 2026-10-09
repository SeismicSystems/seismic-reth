//! Payload attributes for `engine_forkchoiceUpdated`.

use crate::{join_timestamp_millis, split_timestamp_millis};
use alloy_rpc_types_engine::PayloadAttributes;
use serde::{Deserialize, Serialize};

/// Seismic payload attributes: the stock Ethereum [`PayloadAttributes`] plus the sub-second
/// component of the block timestamp.
///
/// `inner.timestamp` is in Unix seconds, `timestamp_millis_part` is `0..1000`. Together they
/// define the block time in milliseconds, see [`Self::timestamp_millis`].
///
/// JSON shape (all stock fields are flattened, the extra field is camel-cased):
///
/// ```json
/// {
///   "timestamp": "0x6a1b2c3d",
///   "timestampMillisPart": "0x7b",
///   "prevRandao": "0x…",
///   "suggestedFeeRecipient": "0x…",
///   "withdrawals": [],
///   "parentBeaconBlockRoot": "0x…"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeismicPayloadAttributes {
    /// The stock Ethereum payload attributes. `timestamp` is in Unix seconds.
    #[serde(flatten)]
    pub inner: PayloadAttributes,
    /// Sub-second (milliseconds) component of the block timestamp, `0..1000`.
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp_millis_part: u64,
}

impl SeismicPayloadAttributes {
    /// Wraps stock attributes with an explicit sub-second component.
    pub const fn new(inner: PayloadAttributes, timestamp_millis_part: u64) -> Self {
        Self { inner, timestamp_millis_part }
    }

    /// Builds attributes from a Unix millisecond block time, splitting it into the stock seconds
    /// `timestamp` and the sub-second component.
    pub const fn from_timestamp_millis(
        mut inner: PayloadAttributes,
        timestamp_millis: u64,
    ) -> Self {
        let (timestamp, timestamp_millis_part) = split_timestamp_millis(timestamp_millis);
        inner.timestamp = timestamp;
        Self { inner, timestamp_millis_part }
    }

    /// Returns the block time in Unix seconds.
    pub const fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    /// Returns the block time in Unix milliseconds.
    pub const fn timestamp_millis(&self) -> u64 {
        join_timestamp_millis(self.inner.timestamp, self.timestamp_millis_part)
    }
}

impl From<PayloadAttributes> for SeismicPayloadAttributes {
    /// Wraps stock attributes with a zero sub-second component.
    fn from(inner: PayloadAttributes) -> Self {
        Self::new(inner, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use serde_json::json;

    fn attrs() -> SeismicPayloadAttributes {
        SeismicPayloadAttributes::from_timestamp_millis(
            PayloadAttributes {
                timestamp: 0,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::ZERO),
            },
            1_700_000_000_123,
        )
    }

    #[test]
    fn splits_millis() {
        let attrs = attrs();
        assert_eq!(attrs.timestamp(), 1_700_000_000);
        assert_eq!(attrs.timestamp_millis_part, 123);
        assert_eq!(attrs.timestamp_millis(), 1_700_000_000_123);
    }

    #[test]
    fn json_shape_is_flat() {
        let value = serde_json::to_value(attrs()).unwrap();
        assert_eq!(
            value,
            json!({
                "timestamp": "0x6553f100",
                "timestampMillisPart": "0x7b",
                "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "suggestedFeeRecipient": "0x0000000000000000000000000000000000000000",
                "withdrawals": [],
                "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            })
        );
        let decoded: SeismicPayloadAttributes = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, attrs());
    }

    #[test]
    fn millis_part_is_required() {
        let mut value = serde_json::to_value(attrs()).unwrap();
        value.as_object_mut().unwrap().remove("timestampMillisPart");
        assert!(serde_json::from_value::<SeismicPayloadAttributes>(value).is_err());
    }
}
