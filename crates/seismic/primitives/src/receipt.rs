use alloy_consensus::{
    proofs::ordered_trie_root_with_encoder, Eip2718EncodableReceipt, Eip658Value, Receipt,
    ReceiptWithBloom, RlpDecodableReceipt, RlpEncodableReceipt, TxReceipt, Typed2718,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bloom, Log, B256};
use alloy_rlp::{BufMut, Decodable, Header};
use reth_primitives_traits::InMemorySize;
use seismic_alloy_consensus::SeismicTxType;

/// Typed ethereum transaction receipt.
/// Receipt containing result of transaction execution.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum SeismicReceipt {
    /// Legacy receipt
    Legacy(Receipt),
    /// EIP-2930 receipt
    Eip2930(Receipt),
    /// EIP-1559 receipt
    Eip1559(Receipt),
    /// EIP-7702 receipt
    Eip7702(Receipt),
    /// Seismic receipt
    Seismic(Receipt),
}

impl Default for SeismicReceipt {
    fn default() -> Self {
        Self::Legacy(Default::default())
    }
}

impl SeismicReceipt {
    /// Returns [`SeismicTxType`] of the receipt.
    pub const fn tx_type(&self) -> SeismicTxType {
        match self {
            Self::Legacy(_) => SeismicTxType::Legacy,
            Self::Eip2930(_) => SeismicTxType::Eip2930,
            Self::Eip1559(_) => SeismicTxType::Eip1559,
            Self::Eip7702(_) => SeismicTxType::Eip7702,
            Self::Seismic(_) => SeismicTxType::Seismic,
        }
    }

    /// Returns inner [`Receipt`],
    pub const fn as_receipt(&self) -> &Receipt {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip7702(receipt) |
            Self::Seismic(receipt) => receipt,
        }
    }

    /// Returns a mutable reference to the inner [`Receipt`],
    pub const fn as_receipt_mut(&mut self) -> &mut Receipt {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip7702(receipt) |
            Self::Seismic(receipt) => receipt,
        }
    }

    /// Returns length of RLP-encoded receipt fields with the given [`Bloom`] without an RLP header.
    pub fn rlp_encoded_fields_length(&self, bloom: &Bloom) -> usize {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip7702(receipt) |
            Self::Seismic(receipt) => receipt.rlp_encoded_fields_length_with_bloom(bloom),
        }
    }

    /// RLP-encodes receipt fields with the given [`Bloom`] without an RLP header.
    pub fn rlp_encode_fields(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(receipt) |
            Self::Eip2930(receipt) |
            Self::Eip1559(receipt) |
            Self::Eip7702(receipt) |
            Self::Seismic(receipt) => receipt.rlp_encode_fields_with_bloom(bloom, out),
        }
    }

    /// Returns RLP header for inner encoding.
    pub fn rlp_header_inner(&self, bloom: &Bloom) -> Header {
        Header { list: true, payload_length: self.rlp_encoded_fields_length(bloom) }
    }

    /// RLP-decodes the receipt from the provided buffer. This does not expect a type byte or
    /// network header.
    pub fn rlp_decode_inner(
        buf: &mut &[u8],
        tx_type: SeismicTxType,
    ) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        match tx_type {
            SeismicTxType::Legacy => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Legacy(receipt), logs_bloom })
            }
            SeismicTxType::Eip2930 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip2930(receipt), logs_bloom })
            }
            SeismicTxType::Eip1559 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip1559(receipt), logs_bloom })
            }
            SeismicTxType::Eip7702 => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Eip7702(receipt), logs_bloom })
            }
            SeismicTxType::Seismic => {
                let ReceiptWithBloom { receipt, logs_bloom } =
                    RlpDecodableReceipt::rlp_decode_with_bloom(buf)?;
                Ok(ReceiptWithBloom { receipt: Self::Seismic(receipt), logs_bloom })
            }
        }
    }

    /// Calculates the receipt root for a header for the reference type of [Receipt].
    ///
    /// NOTE: Prefer `proofs::calculate_receipt_root` if you have log blooms memoized.
    pub fn calculate_receipt_root_no_memo(receipts: &[Self]) -> B256 {
        ordered_trie_root_with_encoder(receipts, |r, buf| r.with_bloom_ref().encode_2718(buf))
    }
}

impl Eip2718EncodableReceipt for SeismicReceipt {
    fn eip2718_encoded_length_with_bloom(&self, bloom: &Bloom) -> usize {
        !self.tx_type().is_legacy() as usize + self.rlp_header_inner(bloom).length_with_payload()
    }

    fn eip2718_encode_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        if !self.tx_type().is_legacy() {
            out.put_u8(self.tx_type() as u8);
        }
        self.rlp_header_inner(bloom).encode(out);
        self.rlp_encode_fields(bloom, out);
    }
}

impl RlpEncodableReceipt for SeismicReceipt {
    fn rlp_encoded_length_with_bloom(&self, bloom: &Bloom) -> usize {
        let mut len = self.eip2718_encoded_length_with_bloom(bloom);
        if !self.tx_type().is_legacy() {
            len += Header {
                list: false,
                payload_length: self.eip2718_encoded_length_with_bloom(bloom),
            }
            .length();
        }

        len
    }

    fn rlp_encode_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        if !self.tx_type().is_legacy() {
            Header { list: false, payload_length: self.eip2718_encoded_length_with_bloom(bloom) }
                .encode(out);
        }
        self.eip2718_encode_with_bloom(bloom, out);
    }
}

impl RlpDecodableReceipt for SeismicReceipt {
    fn rlp_decode_with_bloom(buf: &mut &[u8]) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        let header_buf = &mut &**buf;
        let header = Header::decode(header_buf)?;

        // Legacy receipt, reuse initial buffer without advancing
        if header.list {
            return Self::rlp_decode_inner(buf, SeismicTxType::Legacy)
        }

        // Otherwise, advance the buffer and try decoding type flag followed by receipt
        *buf = *header_buf;

        let remaining = buf.len();
        let tx_type = SeismicTxType::decode(buf)?;
        let this = Self::rlp_decode_inner(buf, tx_type)?;

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(this)
    }
}

impl TxReceipt for SeismicReceipt {
    type Log = Log;

    fn status_or_post_state(&self) -> Eip658Value {
        self.as_receipt().status_or_post_state()
    }

    fn status(&self) -> bool {
        self.as_receipt().status()
    }

    fn bloom(&self) -> Bloom {
        self.as_receipt().bloom()
    }

    fn cumulative_gas_used(&self) -> u64 {
        self.as_receipt().cumulative_gas_used()
    }

    fn logs(&self) -> &[Log] {
        self.as_receipt().logs()
    }
}

impl Typed2718 for SeismicReceipt {
    fn ty(&self) -> u8 {
        self.tx_type().into()
    }
}

impl InMemorySize for SeismicReceipt {
    fn size(&self) -> usize {
        self.as_receipt().size()
    }
}

impl reth_primitives_traits::Receipt for SeismicReceipt {}

#[cfg(feature = "reth-codec")]
mod compact {
    use super::*;
    use alloc::borrow::Cow;
    use reth_codecs::Compact;

    #[derive(reth_codecs::CompactZstd)]
    #[reth_zstd(
        compressor = reth_zstd_compressors::RECEIPT_COMPRESSOR,
        decompressor = reth_zstd_compressors::RECEIPT_DECOMPRESSOR
    )]
    struct CompactSeismicReceipt<'a> {
        tx_type: SeismicTxType,
        success: bool,
        cumulative_gas_used: u64,
        #[expect(clippy::owned_cow)]
        logs: Cow<'a, Vec<Log>>,
    }

    impl<'a> From<&'a SeismicReceipt> for CompactSeismicReceipt<'a> {
        fn from(receipt: &'a SeismicReceipt) -> Self {
            Self {
                tx_type: receipt.tx_type(),
                success: receipt.status(),
                cumulative_gas_used: receipt.cumulative_gas_used(),
                logs: Cow::Borrowed(&receipt.as_receipt().logs),
            }
        }
    }

    impl From<CompactSeismicReceipt<'_>> for SeismicReceipt {
        fn from(receipt: CompactSeismicReceipt<'_>) -> Self {
            let CompactSeismicReceipt { tx_type, success, cumulative_gas_used, logs } = receipt;

            let inner =
                Receipt { status: success.into(), cumulative_gas_used, logs: logs.into_owned() };

            match tx_type {
                SeismicTxType::Legacy => Self::Legacy(inner),
                SeismicTxType::Eip2930 => Self::Eip2930(inner),
                SeismicTxType::Eip1559 => Self::Eip1559(inner),
                SeismicTxType::Eip7702 => Self::Eip7702(inner),
                SeismicTxType::Seismic => Self::Seismic(inner),
            }
        }
    }

    impl Compact for SeismicReceipt {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: bytes::BufMut + AsMut<[u8]>,
        {
            CompactSeismicReceipt::from(self).to_compact(buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            let (receipt, buf) = CompactSeismicReceipt::from_compact(buf, len);
            (receipt.into(), buf)
        }
    }
}

#[cfg(all(feature = "serde", feature = "serde-bincode-compat"))]
pub(super) mod serde_bincode_compat {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::SeismicReceipt`] serde implementation.
    ///
    /// Intended to use with the [`serde_with::serde_as`] macro in the following way:
    /// ```rust
    /// use reth_seismic_primitives::{serde_bincode_compat, SeismicReceipt};
    /// use serde::{de::DeserializeOwned, Deserialize, Serialize};
    /// use serde_with::serde_as;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct Data {
    ///     #[serde_as(as = "serde_bincode_compat::SeismicReceipt<'_>")]
    ///     receipt: SeismicReceipt,
    /// }
    /// ```
    #[derive(Debug, Serialize, Deserialize)]
    pub enum SeismicReceipt<'a> {
        /// Legacy receipt
        Legacy(alloy_consensus::serde_bincode_compat::Receipt<'a, alloy_primitives::Log>),
        /// EIP-2930 receipt
        Eip2930(alloy_consensus::serde_bincode_compat::Receipt<'a, alloy_primitives::Log>),
        /// EIP-1559 receipt
        Eip1559(alloy_consensus::serde_bincode_compat::Receipt<'a, alloy_primitives::Log>),
        /// EIP-7702 receipt
        Eip7702(alloy_consensus::serde_bincode_compat::Receipt<'a, alloy_primitives::Log>),
        /// Seismic receipt
        Seismic(alloy_consensus::serde_bincode_compat::Receipt<'a, alloy_primitives::Log>),
    }

    impl<'a> From<&'a super::SeismicReceipt> for SeismicReceipt<'a> {
        fn from(value: &'a super::SeismicReceipt) -> Self {
            match value {
                super::SeismicReceipt::Legacy(receipt) => Self::Legacy(receipt.into()),
                super::SeismicReceipt::Eip2930(receipt) => Self::Eip2930(receipt.into()),
                super::SeismicReceipt::Eip1559(receipt) => Self::Eip1559(receipt.into()),
                super::SeismicReceipt::Eip7702(receipt) => Self::Eip7702(receipt.into()),
                super::SeismicReceipt::Seismic(receipt) => Self::Seismic(receipt.into()),
            }
        }
    }

    impl<'a> From<SeismicReceipt<'a>> for super::SeismicReceipt {
        fn from(value: SeismicReceipt<'a>) -> Self {
            match value {
                SeismicReceipt::Legacy(receipt) => Self::Legacy(receipt.into()),
                SeismicReceipt::Eip2930(receipt) => Self::Eip2930(receipt.into()),
                SeismicReceipt::Eip1559(receipt) => Self::Eip1559(receipt.into()),
                SeismicReceipt::Eip7702(receipt) => Self::Eip7702(receipt.into()),
                SeismicReceipt::Seismic(receipt) => Self::Seismic(receipt.into()),
            }
        }
    }

    impl SerializeAs<super::SeismicReceipt> for SeismicReceipt<'_> {
        fn serialize_as<S>(source: &super::SeismicReceipt, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            SeismicReceipt::<'_>::from(source).serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::SeismicReceipt> for SeismicReceipt<'de> {
        fn deserialize_as<D>(deserializer: D) -> Result<super::SeismicReceipt, D::Error>
        where
            D: Deserializer<'de>,
        {
            SeismicReceipt::<'_>::deserialize(deserializer).map(Into::into)
        }
    }

    impl reth_primitives_traits::serde_bincode_compat::SerdeBincodeCompat for super::SeismicReceipt {
        type BincodeRepr<'a> = SeismicReceipt<'a>;

        fn as_repr(&self) -> Self::BincodeRepr<'_> {
            self.into()
        }

        fn from_repr(repr: Self::BincodeRepr<'_>) -> Self {
            repr.into()
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::{receipt::serde_bincode_compat, SeismicReceipt};
        use arbitrary::Arbitrary;
        use rand::Rng;
        use serde::{Deserialize, Serialize};
        use serde_with::serde_as;

        #[test]
        fn test_tx_bincode_roundtrip() {
            #[serde_as]
            #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
            struct Data {
                #[serde_as(as = "serde_bincode_compat::SeismicReceipt<'_>")]
                reseipt: SeismicReceipt,
            }

            let mut bytes = [0u8; 1024];
            rand::thread_rng().fill(bytes.as_mut_slice());
            let mut data = Data {
                reseipt: SeismicReceipt::arbitrary(&mut arbitrary::Unstructured::new(&bytes))
                    .unwrap(),
            };
            let success = data.reseipt.as_receipt_mut().status.coerce_status();
            // // ensure we don't have an invalid poststate variant
            data.reseipt.as_receipt_mut().status = success.into();

            let encoded = bincode::serialize(&data).unwrap();
            let decoded: Data = bincode::deserialize(&encoded).unwrap();
            assert_eq!(decoded, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{address, b256, bytes, hex_literal::hex, Bytes};
    use alloy_rlp::Encodable;
    use reth_codecs::Compact;

    #[test]
    #[cfg(feature = "reth-codec")]
    fn test_decode_receipt() {
        reth_codecs::test_utils::test_decode::<SeismicReceipt>(&hex!(
            "c428b52ffd23fc42696156b10200f034792b6a94c3850215c2fef7aea361a0c31b79d9a32652eefc0d4e2e730036061cff7344b6fc6132b50cda0ed810a991ae58ef013150c12b2522533cb3b3a8b19b7786a8b5ff1d3cdc84225e22b02def168c8858df"
        ));
    }

    // Test vector from: https://eips.ethereum.org/EIPS/eip-2481
    #[test]
    fn encode_legacy_receipt() {
        let expected = hex!("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff");

        let mut data = Vec::with_capacity(expected.length());
        let receipt = ReceiptWithBloom {
            receipt: SeismicReceipt::Legacy(Receipt {
                status: Eip658Value::Eip658(false),
                cumulative_gas_used: 0x1,
                logs: vec![Log::new_unchecked(
                    address!("0x0000000000000000000000000000000000000011"),
                    vec![
                        b256!("0x000000000000000000000000000000000000000000000000000000000000dead"),
                        b256!("0x000000000000000000000000000000000000000000000000000000000000beef"),
                    ],
                    bytes!("0100ff"),
                )],
            }),
            logs_bloom: [0; 256].into(),
        };

        receipt.encode(&mut data);

        // check that the rlp length equals the length of the expected rlp
        assert_eq!(receipt.length(), expected.len());
        assert_eq!(data, expected);
    }

    // Test vector from: https://eips.ethereum.org/EIPS/eip-2481
    #[test]
    fn decode_legacy_receipt() {
        let data = hex!("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff");

        // EIP658Receipt
        let expected = ReceiptWithBloom {
            receipt: SeismicReceipt::Legacy(Receipt {
                status: Eip658Value::Eip658(false),
                cumulative_gas_used: 0x1,
                logs: vec![Log::new_unchecked(
                    address!("0x0000000000000000000000000000000000000011"),
                    vec![
                        b256!("0x000000000000000000000000000000000000000000000000000000000000dead"),
                        b256!("0x000000000000000000000000000000000000000000000000000000000000beef"),
                    ],
                    bytes!("0100ff"),
                )],
            }),
            logs_bloom: [0; 256].into(),
        };

        let receipt = ReceiptWithBloom::decode(&mut &data[..]).unwrap();
        assert_eq!(receipt, expected);
    }

    #[test]
    fn test_encode_2718_length() {
        let receipt = ReceiptWithBloom {
            receipt: SeismicReceipt::Eip1559(Receipt {
                status: Eip658Value::Eip658(true),
                cumulative_gas_used: 21000,
                logs: vec![],
            }),
            logs_bloom: Bloom::default(),
        };

        let encoded = receipt.encoded_2718();
        assert_eq!(
            encoded.len(),
            receipt.encode_2718_len(),
            "Encoded length should match the actual encoded data length"
        );

        // Test for legacy receipt as well
        let legacy_receipt = ReceiptWithBloom {
            receipt: SeismicReceipt::Legacy(Receipt {
                status: Eip658Value::Eip658(true),
                cumulative_gas_used: 21000,
                logs: vec![],
            }),
            logs_bloom: Bloom::default(),
        };

        let legacy_encoded = legacy_receipt.encoded_2718();
        assert_eq!(
            legacy_encoded.len(),
            legacy_receipt.encode_2718_len(),
            "Encoded length for legacy receipt should match the actual encoded data length"
        );
    }
}
