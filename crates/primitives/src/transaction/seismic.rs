use crate::{keccak256, Address, Bytes, ChainId, Signature, TxKind, TxType, B256, U256};
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

fn nonce_to_generic_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce_bytes = nonce.to_be_bytes().to_vec();

    let crypto_nonce_size = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();

    nonce_bytes.resize(crypto_nonce_size, 0); // pad for crypto

    let rng = AesRng::default();
    let libnonce = Aes256Gcm::generate_nonce(rng);

    GenericArray::clone_from_slice(&nonce_bytes)
}

pub trait Encryptable: Encodable + Decodable {}
impl<T: Encodable + Decodable> Encryptable for T {}

fn decrypt<T>(ciphertext: &Vec<u8>, nonce: u64) -> alloy_rlp::Result<T>
where
    T: Encryptable,
{
    let cipher = Aes256Gcm::new(&AES_KEY);
    let nonce = nonce_to_generic_array(nonce);
    let buf = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_err| Error::Custom("Failed to decrypt seismic transaction"))?;
    T::decode(&mut &buf[..])
}

fn encrypt<T: Encryptable>(plaintext: &T, nonce: u64) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(&AES_KEY);
    let nonce = nonce_to_generic_array(nonce);
    let mut buf = Vec::new();
    plaintext.encode(&mut buf);
    // Returns an error if the buffer has insufficient capacity to store the
    // resulting ciphertext message.
    cipher
        .encrypt(&nonce, buf.as_ref())
        .map_err(|_err| Error::Custom("Failed to encrypt seismic transaction"))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(any(test, feature = "reth-codec"), derive(Compact))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct DecryptedTx {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(any(test, feature = "reth-codec"), derive(Compact))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct EncryptedTx {
    chain_id: ChainId,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: TxKind,
    value: U256,
    input: Vec<u8>,
}

impl EncryptedTx {
    pub fn from_decrypted_tx(decrypted_tx: &DecryptedTx) -> Result<Self, Error> {
        Ok(EncryptedTx {
            chain_id: decrypted_tx.chain_id,
            nonce: decrypted_tx.nonce,
            gas_price: decrypted_tx.gas_price,
            gas_limit: decrypted_tx.gas_limit,
            to: decrypted_tx.to.clone(),
            value: decrypted_tx.value.clone(),
            input: encrypt(&decrypted_tx.input, decrypted_tx.nonce)?,
        })
    }

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
}

impl Encodable for EncryptedTx {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.gas_price.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.encode(out);
    }

    fn length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.gas_price.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.length()
    }
}

impl Decodable for EncryptedTx {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let chain_id = Decodable::decode(buf)?;
        let nonce = Decodable::decode(buf)?;
        let gas_price = Decodable::decode(buf)?;
        let gas_limit = Decodable::decode(buf)?;
        let to = Decodable::decode(buf)?;
        let value = Decodable::decode(buf)?;
        let input = Decodable::decode(buf)?;
        Ok(EncryptedTx { chain_id, nonce, gas_price, gas_limit, to, value, input })
    }
}

impl DecryptedTx {
    pub fn from_encrypted_tx(encrypted_tx: &EncryptedTx) -> alloy_rlp::Result<Self> {
        let nonce = encrypted_tx.nonce;
        Ok(DecryptedTx {
            chain_id: encrypted_tx.chain_id.clone(),
            nonce: encrypted_tx.nonce,
            gas_price: encrypted_tx.gas_price,
            gas_limit: encrypted_tx.gas_limit,
            to: encrypted_tx.to.clone(),
            value: encrypted_tx.value.clone(),
            input: decrypt::<Bytes>(&encrypted_tx.input, nonce)?,
        })
    }

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
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct TxSeismic {
    pub encrypted_tx: EncryptedTx,
    pub decrypted_tx: DecryptedTx,
}

impl Default for TxSeismic {
    fn default() -> Self {
        let decrypted_tx = DecryptedTx::default();
        TxSeismic::new_from_decrypted_tx(decrypted_tx)
    }
}

impl Serialize for TxSeismic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.encrypted_tx.serialize(serializer)
    }
}

impl<'de, 'a> Deserialize<'de> for TxSeismic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encrypted_tx = EncryptedTx::deserialize(deserializer)?;
        TxSeismic::new_from_encrypted_tx(encrypted_tx).map_err(serde::de::Error::custom)
    }
}

impl Clone for TxSeismic {
    fn clone(&self) -> Self {
        TxSeismic {
            encrypted_tx: self.encrypted_tx.clone(),
            decrypted_tx: self.decrypted_tx.clone(),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TxSeismic {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let encrypted_tx: EncryptedTx = u.arbitrary()?;
        TxSeismic::new_from_encrypted_tx(encrypted_tx)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for TxSeismic {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut buf = Vec::new();
        self.decrypted_tx.to_compact(&mut buf) 
    }
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (decrypted_tx, buf) = DecryptedTx::from_compact(buf, len);
        return (
            TxSeismic::new_from_decrypted_tx(decrypted_tx),
            &buf[len..],
        );
    }
}
macro_rules! generate_decrypted_getters {
    ($($field:ident: $type:ty),*) => {
        $(
            // Create getter function for each field using paste to concatenate function names #[inline]
            pub const fn $field(&self) -> &$type {
                &self.decrypted_tx.$field
            }
        )*
    };
}

macro_rules! generate_encrypted_getters {
    ($($field:ident: $type:ty),*) => {
        $(
            paste! {
                #[inline]
                pub const fn [<encrypted_ $field>](&self) -> &$type {
                    &self.encrypted_tx.$field
                }
            }

        )*
    };
}

macro_rules! generate_decrypted_setters {
    ($($field:ident: $type:ty),* $(,)?) => {
        $(
            paste! {
                // Create setter function for each field using paste to concatenate function names
                #[inline]
                pub fn [<set_ $field>](&mut self, value: $type) {
                    self.decrypted_tx.$field = value;
                }
            }
        )*
    };
}

impl TxSeismic {
    /// Constructors
    pub fn new_from_encrypted_params(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        encrypted_input: Vec<u8>,
    ) -> Result<Self, Error> {
        let encrypted_tx = EncryptedTx {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input: encrypted_input.clone(),
        };
        TxSeismic::new_from_encrypted_tx(encrypted_tx)
    }

    pub fn new_from_encrypted_tx(encrypted_tx: EncryptedTx) -> alloy_rlp::Result<Self> {
        let decrypted_tx = DecryptedTx::from_encrypted_tx(&encrypted_tx)?;
        Ok(TxSeismic { encrypted_tx, decrypted_tx })
    }

    // should only be used for testing purpose
    pub fn new_from_decrypted_params(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        decrypted_input: Bytes,
    ) -> Self {
        let decrypted_tx = DecryptedTx {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input: decrypted_input,
        };
        TxSeismic::new_from_decrypted_tx(decrypted_tx)
    }

    pub fn new_from_decrypted_tx(decrypted_tx: DecryptedTx) -> Self {
        let encrypted_tx = EncryptedTx::from_decrypted_tx(&decrypted_tx)
            .expect("Failed to encrypt seismic transaction");
        TxSeismic { encrypted_tx, decrypted_tx }
    }

    generate_decrypted_setters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Bytes
    );
    generate_decrypted_getters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Bytes
    );
    generate_encrypted_getters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Vec<u8>
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
        let encrypted_tx = Decodable::decode(buf)?;
        let tx = TxSeismic::new_from_encrypted_tx(encrypted_tx)?;
        Ok(tx)
    }

    // functions imported from TxEip4844
    /// Calculates a heuristic for the in-memory size of the [`TxSeismic`] transaction.
    /// In memory stores the decrypted transaction and the encrypted transaction.
    /// Out of memory stores the encrypted transaction. This is why size and fields_len are
    /// diffenrent.
    #[inline]
    pub fn size(&self) -> usize {
        self.encrypted_tx.size() + self.decrypted_tx.size()
    }

    /// Outputs the length of the transaction's fields, without a RLP header or length of the
    /// eip155 fields.
    pub(crate) fn fields_len(&self) -> usize {
        self.encrypted_tx.length()
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header or
    /// eip155 fields.
    pub(crate) fn encode_fields(&self, out: &mut dyn bytes::BufMut) {
        self.encrypted_tx.encode(out);
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
    use core::str::FromStr;

    use super::*;

    #[test]
    fn test_encoding_encryption_leakage() {
        // initialize an encrypted_tx
        let decrypted_input: Bytes = Bytes::from(vec![1, 2, 3, 4, 5]);
        let decrypted_tx = DecryptedTx {
            chain_id: 4u64,
            nonce: 2,
            gas_price: 1000000000,
            gas_limit: 100000,
            to: Address::from_str("d3e8763675e4c425df46cc3b5c0f6cbdac396046").unwrap().into(),
            value: U256::from(1000000000000000u64),
            input: decrypted_input.clone(),
        };
        let encrypted_tx = EncryptedTx::from_decrypted_tx(&decrypted_tx)
            .expect("Failed to encrypt seismic transaction");

        // encode it
        let mut encrypted_tx_encoding = Vec::new();
        encrypted_tx.encode(&mut encrypted_tx_encoding);

        // initialize a TxSeismic
        let tx_seismic = TxSeismic::new_from_encrypted_tx(encrypted_tx.clone())
            .expect("Failed to create TxSeismic from encrypted_tx");

        // encode it
        let mut tx_seismic_encoding = Vec::new();
        tx_seismic.encode_fields(&mut tx_seismic_encoding);

        // check the encoding is the same as encoding the encrypted_tx
        assert_eq!(encrypted_tx_encoding, tx_seismic_encoding);

        // decode it
        let decoded_tx_seismic = TxSeismic::decode_inner(&mut &tx_seismic_encoding[..]).unwrap();

        // check that the resulted encrypted_tx is the same as the original encrypted_tx
        assert_eq!(decoded_tx_seismic.encrypted_tx, encrypted_tx);
        assert_eq!(decoded_tx_seismic.decrypted_tx, decrypted_tx);
        assert_eq!(decrypted_input, *decoded_tx_seismic.input());
    }
}
