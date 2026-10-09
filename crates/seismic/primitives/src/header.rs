//! Seismic block header.
//!
//! The Seismic header is a standard Ethereum [`Header`] extended with a sub-second timestamp
//! component. `inner.timestamp` keeps its standard meaning (Unix **seconds**), so every upstream
//! consumer — hardfork activation, blob params, the `TIMESTAMP` opcode, tooling — sees a normal
//! Ethereum header. Millisecond block times are exposed through
//! [`SeismicHeader::timestamp_millis`].

use alloy_consensus::{BlockHeader, Header, Sealable};
use alloy_primitives::{keccak256, Address, BlockNumber, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Number of milliseconds in one second.
pub const MILLIS_PER_SECOND: u64 = 1000;

/// Seismic block header.
///
/// RLP-encoded as `[timestamp_millis_part, inner]`, where `inner` is the standard Ethereum header
/// list. The block hash is the keccak of that outer list, so it commits to the sub-second
/// component.
///
/// Serialized as the flattened standard header fields plus `timestampMillisPart`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SeismicHeader {
    /// Sub-second (milliseconds) component of the timestamp, `0..1000`.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub timestamp_millis_part: u64,
    /// The standard Ethereum header. `timestamp` is in Unix seconds.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub inner: Header,
}

impl SeismicHeader {
    /// Wraps a standard header with an explicit sub-second component.
    pub const fn new(inner: Header, timestamp_millis_part: u64) -> Self {
        Self { timestamp_millis_part, inner }
    }

    /// Returns the block time in Unix milliseconds.
    ///
    /// Saturates instead of wrapping on overflow.
    pub const fn timestamp_millis(&self) -> u64 {
        self.inner
            .timestamp
            .saturating_mul(MILLIS_PER_SECOND)
            .saturating_add(self.timestamp_millis_part)
    }

    /// Sets the block time from Unix milliseconds, splitting it into the standard seconds
    /// `timestamp` and the sub-second component.
    pub const fn set_timestamp_millis(&mut self, timestamp_millis: u64) {
        self.inner.timestamp = timestamp_millis / MILLIS_PER_SECOND;
        self.timestamp_millis_part = timestamp_millis % MILLIS_PER_SECOND;
    }

    /// Returns `true` if the sub-second component is in range.
    pub const fn has_valid_millis_part(&self) -> bool {
        self.timestamp_millis_part < MILLIS_PER_SECOND
    }
}

impl From<Header> for SeismicHeader {
    /// Wraps a standard header with a zero sub-second component.
    fn from(inner: Header) -> Self {
        Self::new(inner, 0)
    }
}

impl AsRef<Self> for SeismicHeader {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<Header> for SeismicHeader {
    fn as_ref(&self) -> &Header {
        &self.inner
    }
}

impl BlockHeader for SeismicHeader {
    fn parent_hash(&self) -> B256 {
        self.inner.parent_hash()
    }

    fn ommers_hash(&self) -> B256 {
        self.inner.ommers_hash()
    }

    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    fn state_root(&self) -> B256 {
        self.inner.state_root()
    }

    fn transactions_root(&self) -> B256 {
        self.inner.transactions_root()
    }

    fn receipts_root(&self) -> B256 {
        self.inner.receipts_root()
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.inner.withdrawals_root()
    }

    fn logs_bloom(&self) -> Bloom {
        self.inner.logs_bloom()
    }

    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    fn number(&self) -> BlockNumber {
        self.inner.number()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_used(&self) -> u64 {
        self.inner.gas_used()
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn mix_hash(&self) -> Option<B256> {
        self.inner.mix_hash()
    }

    fn nonce(&self) -> Option<B64> {
        self.inner.nonce()
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.inner.base_fee_per_gas()
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used()
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.inner.excess_blob_gas()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn requests_hash(&self) -> Option<B256> {
        self.inner.requests_hash()
    }

    fn extra_data(&self) -> &Bytes {
        self.inner.extra_data()
    }
}

impl Sealable for SeismicHeader {
    fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

impl reth_primitives_traits::InMemorySize for SeismicHeader {
    fn size(&self) -> usize {
        let Self { timestamp_millis_part, inner } = self;
        timestamp_millis_part.size() + inner.size()
    }
}

impl reth_primitives_traits::BlockHeader for SeismicHeader {}

#[cfg(any(test, feature = "test-utils"))]
impl reth_primitives_traits::test_utils::TestHeader for SeismicHeader {
    fn set_parent_hash(&mut self, hash: B256) {
        self.inner.parent_hash = hash;
    }

    fn set_block_number(&mut self, number: BlockNumber) {
        self.inner.number = number;
    }

    fn set_state_root(&mut self, state_root: B256) {
        self.inner.state_root = state_root;
    }

    fn set_difficulty(&mut self, difficulty: U256) {
        self.inner.difficulty = difficulty;
    }
}

#[cfg(feature = "reth-codec")]
mod codec {
    use super::SeismicHeader;
    use alloy_consensus::Header;

    /// Compact layout helper. The variable-length [`Header`] must be the last field.
    #[derive(Clone, Debug, Default, Eq, Hash, PartialEq, reth_codecs::Compact)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    struct SeismicHeaderCompact {
        timestamp_millis_part: u64,
        inner: Header,
    }

    impl reth_codecs::Compact for SeismicHeader {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
        {
            SeismicHeaderCompact {
                timestamp_millis_part: self.timestamp_millis_part,
                inner: self.inner.clone(),
            }
            .to_compact(buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            let (compact, buf) = SeismicHeaderCompact::from_compact(buf, len);
            (
                Self { timestamp_millis_part: compact.timestamp_millis_part, inner: compact.inner },
                buf,
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use reth_codecs::Compact;

        #[test]
        fn compact_has_unused_bits() {
            // Add future fields through an extension type instead of exhausting the bitflag.
            assert_ne!(SeismicHeaderCompact::bitflag_unused_bits(), 0);
        }

        #[test]
        fn compact_roundtrip() {
            let header = SeismicHeader {
                timestamp_millis_part: 123,
                inner: Header { number: 7, timestamp: 1_700_000_000, ..Default::default() },
            };
            let mut buf = vec![];
            let len = header.to_compact(&mut buf);
            // Like upstream's `Header`, the trailing header field does not advance the buffer.
            let (decoded, _) = SeismicHeader::from_compact(&buf, len);
            assert_eq!(decoded, header);
        }
    }
}

/// Bincode-compatible serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub(super) mod serde_bincode_compat {
    use alloy_consensus::serde_bincode_compat::Header;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::SeismicHeader`] serde implementation.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SeismicHeader<'a> {
        timestamp_millis_part: u64,
        inner: Header<'a>,
    }

    impl<'a> From<&'a super::SeismicHeader> for SeismicHeader<'a> {
        fn from(value: &'a super::SeismicHeader) -> Self {
            Self {
                timestamp_millis_part: value.timestamp_millis_part,
                inner: Header::from(&value.inner),
            }
        }
    }

    impl<'a> From<SeismicHeader<'a>> for super::SeismicHeader {
        fn from(value: SeismicHeader<'a>) -> Self {
            Self { timestamp_millis_part: value.timestamp_millis_part, inner: value.inner.into() }
        }
    }

    impl SerializeAs<super::SeismicHeader> for SeismicHeader<'_> {
        fn serialize_as<S>(source: &super::SeismicHeader, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            SeismicHeader::<'_>::from(source).serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::SeismicHeader> for SeismicHeader<'de> {
        fn deserialize_as<D>(deserializer: D) -> Result<super::SeismicHeader, D::Error>
        where
            D: Deserializer<'de>,
        {
            SeismicHeader::<'_>::deserialize(deserializer).map(Into::into)
        }
    }

    impl reth_primitives_traits::serde_bincode_compat::SerdeBincodeCompat for super::SeismicHeader {
        type BincodeRepr<'a> = SeismicHeader<'a>;

        fn as_repr(&self) -> Self::BincodeRepr<'_> {
            self.into()
        }

        fn from_repr(repr: Self::BincodeRepr<'_>) -> Self {
            repr.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Decodable;

    fn header() -> SeismicHeader {
        SeismicHeader {
            timestamp_millis_part: 123,
            inner: Header {
                number: 7,
                timestamp: 1_700_000_000,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(7),
                withdrawals_root: Some(B256::repeat_byte(0x11)),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::ZERO),
                requests_hash: Some(B256::repeat_byte(0x33)),
                ..Default::default()
            },
        }
    }

    #[test]
    fn millis_roundtrip() {
        let mut header = header();
        assert_eq!(header.timestamp_millis(), 1_700_000_000_123);
        header.set_timestamp_millis(999);
        assert_eq!((header.timestamp(), header.timestamp_millis_part), (0, 999));
        header.set_timestamp_millis(1_000);
        assert_eq!((header.timestamp(), header.timestamp_millis_part), (1, 0));
        assert!(header.has_valid_millis_part());
        header.timestamp_millis_part = 1000;
        assert!(!header.has_valid_millis_part());
    }

    #[test]
    fn rlp_roundtrip_and_hash_commits_to_millis() {
        let header = header();
        let encoded = alloy_rlp::encode(&header);
        assert_eq!(SeismicHeader::decode(&mut encoded.as_slice()).unwrap(), header);

        let mut other = header.clone();
        other.timestamp_millis_part += 1;
        assert_ne!(header.hash_slow(), other.hash_slow());
        assert_ne!(header.hash_slow(), header.inner.hash_slow());
    }

    #[test]
    fn delegates_standard_fields() {
        let header = header();
        assert_eq!(header.number(), 7);
        assert_eq!(header.timestamp(), 1_700_000_000);
        assert_eq!(header.gas_limit(), 30_000_000);
        assert_eq!(header.base_fee_per_gas(), Some(7));
        assert_eq!(header.requests_hash(), Some(B256::repeat_byte(0x33)));
        assert_eq!(SeismicHeader::from(header.inner).timestamp_millis_part, 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_is_flat() {
        let value = serde_json::to_value(header()).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object["timestamp"], "0x6553f100");
        assert_eq!(object["timestampMillisPart"], "0x7b");
        assert_eq!(object["number"], "0x7");
        assert!(!object.contains_key("inner"));
        let decoded: SeismicHeader = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, header());
    }
}
