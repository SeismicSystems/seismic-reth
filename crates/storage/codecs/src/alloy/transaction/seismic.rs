//! Compact implementation for [`AlloyTxSeismic`]

use crate::Compact;
use alloy_consensus::{transaction::TxSeismicElements, TxSeismic as AlloyTxSeismic};
use alloy_primitives::{aliases::U96, Bytes, ChainId, TxKind, U256};
use bytes::{Buf, BytesMut};

/// Seismic transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default, Compact)]
#[reth_codecs(crate = "crate")]
#[cfg_attr(
    any(test, feature = "test-utils"),
    derive(arbitrary::Arbitrary, serde::Serialize, serde::Deserialize),
    crate::add_arbitrary_tests(crate, compact)
)]
#[cfg_attr(feature = "test-utils", allow(unreachable_pub), visibility::make(pub))]
pub(crate) struct TxSeismic {
    /// Added as EIP-155: Simple replay attack protection
    chain_id: ChainId,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    gas_price: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    gas_limit: u64,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    value: U256,
    /// seismic elements
    seismic_elements: TxSeismicElements,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    input: Bytes,
}

impl Compact for TxSeismicElements {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut len = 0;
        len += self.encryption_pubkey.serialize().to_compact(buf);

        buf.put_u8(self.message_version);
        len += core::mem::size_of::<u8>();

        let mut cache = BytesMut::new();
        let nonce_len = self.encryption_nonce.to_compact(&mut cache);
        buf.put_u8(nonce_len as u8);
        buf.put_slice(&cache);
        len += nonce_len + 1;

        len
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let encryption_pubkey_compressed_bytes =
            &buf[..seismic_enclave::constants::PUBLIC_KEY_SIZE];
        let encryption_pubkey =
            seismic_enclave::PublicKey::from_slice(encryption_pubkey_compressed_bytes).unwrap();
        buf.advance(seismic_enclave::constants::PUBLIC_KEY_SIZE);

        let (message_version, buf) = (buf[0], &buf[1..]);

        let (nonce_len, buf) = (buf[0], &buf[1..]);
        let (encryption_nonce, buf) = U96::from_compact(buf, nonce_len as usize);
        (Self { encryption_pubkey, encryption_nonce, message_version }, buf)
    }
}

impl Compact for AlloyTxSeismic {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let tx = TxSeismic {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            seismic_elements: self.seismic_elements,
            input: self.input.clone(),
        };

        tx.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (tx, _) = TxSeismic::from_compact(buf, len);

        let alloy_tx = Self {
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            gas_price: tx.gas_price,
            gas_limit: tx.gas_limit,
            to: tx.to,
            value: tx.value,
            seismic_elements: tx.seismic_elements,
            input: tx.input,
        };

        (alloy_tx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, Bytes, TxKind};
    use bytes::BytesMut;
    use seismic_enclave::PublicKey;

    #[test]
    fn test_seismic_tx_compact_roundtrip() {
        // Create a test transaction based on the example in file_context_0
        let tx = AlloyTxSeismic {
            chain_id: 1166721750861005481,
            nonce: 13985005159674441909,
            gas_price: 296133358425745351516777806240018869443,
            gas_limit: 6091425913586946366,
            to: TxKind::Create,
            value: U256::from_str_radix(
                "30997721070913355446596643088712595347117842472993214294164452566768407578853",
                10,
            )
            .unwrap(),
            seismic_elements: TxSeismicElements {
                encryption_pubkey: PublicKey::from_slice(
                    &hex::decode(
                        "02d211b6b0a191b9469bb3674e9c609f453d3801c3e3fd7e0bb00c6cc1e1d941df",
                    )
                    .unwrap(),
                )
                .unwrap(),
                encryption_nonce: 11856476099097235301,
                message_version: 85,
            },
            input: Bytes::from_static(&[0x24]),
        };

        // Encode to compact format
        let mut buf = BytesMut::new();
        let encoded_size = tx.to_compact(&mut buf);

        // Decode from compact format
        let (decoded_tx, _) = AlloyTxSeismic::from_compact(&buf, encoded_size);

        // Verify the roundtrip
        assert_eq!(tx.chain_id, decoded_tx.chain_id);
        assert_eq!(tx.nonce, decoded_tx.nonce);
        assert_eq!(tx.gas_price, decoded_tx.gas_price);
        assert_eq!(tx.gas_limit, decoded_tx.gas_limit);
        assert_eq!(tx.to, decoded_tx.to);
        assert_eq!(tx.value, decoded_tx.value);
        assert_eq!(tx.input, decoded_tx.input);

        // Check seismic elements
        assert_eq!(
            tx.seismic_elements.encryption_pubkey.serialize(),
            decoded_tx.seismic_elements.encryption_pubkey.serialize()
        );
        assert_eq!(
            tx.seismic_elements.encryption_nonce,
            decoded_tx.seismic_elements.encryption_nonce
        );
        assert_eq!(
            tx.seismic_elements.message_version,
            decoded_tx.seismic_elements.message_version
        );
    }
}
