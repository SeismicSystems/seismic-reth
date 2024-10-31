use crate::{keccak256, Bytes, ChainId, Signature, TxKind, TxType, B256, U256};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key,
};
use alloy_rlp::{length_of_length, Decodable, Encodable, Error, Header};
use core::mem;
use once_cell::sync::Lazy;
use paste::paste;

#[cfg(any(test, feature = "reth-codec"))]
use reth_codecs::Compact;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// Static variable that will hold the generated key, initialized lazily
static AES_KEY: Lazy<Key<Aes256Gcm>> = Lazy::new(|| {
    let rng = AesRng::default();
    let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);
    return key;
});

/// Basic encrypted transaction type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(any(test, feature = "reth-codec"), derive(Compact))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct TxSeismic {
    /// encrypted transaction inputted from users
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Bytes,
}

macro_rules! generate_getters {
    ($($field:ident: $type:ty),*) => {
        $(
            paste! {
                /// Create getter function for each decrypted field
                #[inline]
                pub const fn [<$field>](&self) -> &$type {
                    &self.$field
                }
            }

        )*
    };
}

macro_rules! generate_setters {
    ($($field:ident: $type:ty),* $(,)?) => {
        $(
            paste! {
                /// since the transaction content is not supposed to change, this is only for testing functions
                #[inline]
                pub fn [<set_ $field>](&mut self, value: $type) {
                    self.$field = value;
                }
            }
        )*
    };
}

impl TxSeismic {

    generate_getters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Bytes
    );
    generate_setters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Bytes
    );

    /// Decodes the inner [`TxSeismic`] fields from RLP bytes.
    ///
    /// NOTE: This assumes a RLP header has already been decoded, and _just_ decodes the following
    /// RLP fields in the following order:
    ///
    /// - chain_id
    /// - nonce
    /// - gas_price
    /// - gas_limit
    /// - to
    /// - value
    /// - encrypted_input
    pub fn decode_inner(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let chain_id = Decodable::decode(buf)?;
        let nonce = Decodable::decode(buf)?;
        let gas_price = Decodable::decode(buf)?;
        let gas_limit = Decodable::decode(buf)?;
        let to = Decodable::decode(buf)?;
        let value = Decodable::decode(buf)?;
        let input = Decodable::decode(buf)?;
        Ok(TxSeismic { chain_id, nonce, gas_price, gas_limit, to, value, input })
    }

    // functions imported from TxEip4844
    /// Calculates a heuristic for the in-memory size of the [`TxSeismic`] transaction.
    /// In memory stores the decrypted transaction and the encrypted transaction.
    /// Out of memory stores the encrypted transaction. This is why size and fields_len are
    /// diffenrent.
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ChainId>() + // chain_id
        mem::size_of::<u64>() + // nonce
        mem::size_of::<u128>() + // gas_price
        mem::size_of::<u64>() + // gas_limit
        mem::size_of::<u128>() + // max_priority_fee_per_gas
        self.to.size() + // to
        mem::size_of::<U256>() + // value
        self.input.len() // input
    }

    /// Outputs the length of the transaction's fields, without a RLP header or length of the
    /// eip155 fields.
    pub(crate) fn fields_len(&self) -> usize {
        self.chain_id.length() +
            self.nonce.length() +
            self.gas_price.length() +
            self.gas_limit.length() +
            self.to.length() +
            self.value.length() +
            self.input.length()
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header or
    /// eip155 fields.
    pub(crate) fn encode_fields(&self, out: &mut dyn bytes::BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.gas_price.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.encode(out);
    }

    /// Inner encoding function that is used for both rlp [`Encodable`] trait and for calculating
    /// hash that for eip2718 does not require rlp header
    pub(crate) fn encode_with_signature(
        &self,
        signature: &Signature,
        out: &mut dyn bytes::BufMut,
        with_header: bool,
    ) {
        let payload_length = self.fields_len() + signature.payload_len();
        if with_header {
            Header {
                list: false,
                payload_length: 1 + length_of_length(payload_length) + payload_length,
            }
            .encode(out);
        }
        out.put_u8(self.tx_type() as u8);
        let header = Header { list: true, payload_length };
        header.encode(out);
        self.encode_fields(out);
        signature.encode(out);
    }

    /// Output the length of the RLP signed transaction encoding.
    pub(crate) fn payload_len_with_signature(&self, signature: &Signature) -> usize {
        let len = self.payload_len_with_signature_without_header(signature);
        length_of_length(len) + len
    }

    /// Output the length of the RLP signed transaction encoding, _without_ a RLP header.
    pub(crate) fn payload_len_with_signature_without_header(&self, signature: &Signature) -> usize {
        let payload_length = self.fields_len() + signature.payload_len();
        // 'transaction type byte length' + 'header length' + 'payload length'
        1 + length_of_length(payload_length) + payload_length
    }

    /// Get transaction type
    pub(crate) const fn tx_type(&self) -> TxType {
        TxType::Seismic
    }

    /// Encodes the EIP-4844 transaction in RLP for signing.
    ///
    /// This encodes the transaction as:
    /// `tx_type || rlp(chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to,
    /// value, input, access_list, max_fee_per_blob_gas, blob_versioned_hashes)`
    ///
    /// Note that there is no rlp header before the transaction type byte.
    pub(crate) fn encode_for_signing(&self, out: &mut dyn bytes::BufMut) {
        out.put_u8(self.tx_type() as u8);
        Header { list: true, payload_length: self.fields_len() }.encode(out);
        self.encode_fields(out);
    }

    /// Outputs the length of the signature RLP encoding for the transaction.
    pub(crate) fn payload_len_for_signature(&self) -> usize {
        let payload_length = self.fields_len();
        // 'transaction type byte length' + 'header length' + 'payload length'
        1 + length_of_length(payload_length) + payload_length
    }

    /// Outputs the signature hash of the transaction by first encoding without a signature, then
    /// hashing.
    ///
    /// See [`Self::encode_for_signing`] for more information on the encoding format.
    pub(crate) fn signature_hash(&self) -> B256 {
        let mut buf = Vec::with_capacity(self.payload_len_for_signature());
        self.encode_for_signing(&mut buf);
        keccak256(&buf)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use derive_more::FromStr;
    use serde_json::from_value;

    use super::*;

    #[test]
    fn test_encoding_decoding() {
        let tx = TxSeismic {
            chain_id: 4u64,
            nonce: 2,
            gas_price: 1000000000,
            gas_limit: 100000,
            to: Address::from_str("d3e8763675e4c425df46cc3b5c0f6cbdac396046").unwrap().into(),
            value: U256::from(1000000000000000u64),
            input: vec![1, 2, 3].into(),
        };

        let mut encoded_tx = Vec::new();
        tx.encode_fields(&mut encoded_tx);
        let decoded_tx = TxSeismic::decode_inner(&mut &encoded_tx[..]).expect("Failed to decode seismic transaction");

        // check that the decoded transaction matches the original transaction
        assert_eq!(decoded_tx, tx);
    }
}
