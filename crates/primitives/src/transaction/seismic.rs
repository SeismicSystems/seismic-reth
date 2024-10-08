use crate::{keccak256, Bytes, ChainId, Signature, TxKind, TxType, B256, U256};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key,
};
use alloy_rlp::{length_of_length, Decodable, Encodable, Header};
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
    println!("libnonce {:?}", libnonce.len());

    GenericArray::clone_from_slice(&nonce_bytes)
}

fn decrypt<T>(ciphertext: &Vec<u8>, nonce: u64) -> T
where
    T: Decodable,
{
    let cipher = Aes256Gcm::new(&AES_KEY);
    let nonce = nonce_to_generic_array(nonce);
    let buf = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    T::decode(&mut &buf[..]).unwrap_or_else(|err| panic!("Failed to decode: {:?}", err))
}

fn encrypt<T: Encodable>(plaintext: &T, nonce: u64) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&AES_KEY);
    let nonce = nonce_to_generic_array(nonce);
    let mut buf = Vec::new();
    plaintext.encode(&mut buf);
    cipher
        .encrypt(&nonce, buf.as_ref())
        .unwrap_or_else(|err| panic!("Encryption failed: {:?}", err))
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
    pub fn from_decrypted_tx(decrypted_tx: &DecryptedTx) -> Self {
        EncryptedTx {
            chain_id: decrypted_tx.chain_id,
            nonce: decrypted_tx.nonce,
            gas_price: decrypted_tx.gas_price,
            gas_limit: decrypted_tx.gas_limit,
            to: decrypted_tx.to.clone(),
            value: decrypted_tx.value.clone(),
            input: encrypt(&decrypted_tx.input, decrypted_tx.nonce),
        }
    }
}

impl DecryptedTx {
    pub fn from_encrypted_tx(encrypted_tx: &EncryptedTx) -> Self {
        let nonce = encrypted_tx.nonce;
        DecryptedTx {
            chain_id: encrypted_tx.chain_id.clone(),
            nonce: encrypted_tx.nonce,
            gas_price: encrypted_tx.gas_price,
            gas_limit: encrypted_tx.gas_limit,
            to: encrypted_tx.to.clone(),
            value: encrypted_tx.value.clone(),
            input: decrypt::<Bytes>(&encrypted_tx.input, nonce),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct TxSeismic {
    encrypted_tx: Box<EncryptedTx>,
    decrypted_tx: Box<DecryptedTx>,
}

impl Default for TxSeismic {
    fn default() -> Self {
        let encrypted_tx = Box::new(EncryptedTx::default());
        let decrypted_tx = Box::new(DecryptedTx::from_encrypted_tx(&encrypted_tx));
        TxSeismic { encrypted_tx, decrypted_tx }
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
        let decrypted_tx = DecryptedTx::from_encrypted_tx(&encrypted_tx);
        Ok(TxSeismic { encrypted_tx: Box::new(encrypted_tx), decrypted_tx: Box::new(decrypted_tx) })
    }
}

impl Clone for TxSeismic {
    fn clone(&self) -> Self {
        TxSeismic {
            encrypted_tx: Box::new((*self.encrypted_tx).clone()),
            decrypted_tx: Box::new((*self.decrypted_tx).clone()),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TxSeismic {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let encrypted_tx: EncryptedTx = u.arbitrary()?;
        let decrypted_tx = DecryptedTx::from_encrypted_tx(&encrypted_tx);
        Ok(TxSeismic { encrypted_tx: Box::new(encrypted_tx), decrypted_tx: Box::new(decrypted_tx) })
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for TxSeismic {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut buf = Vec::new();
        self.encrypted_tx.to_compact(&mut buf)
    }
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (encrypted_input, buf) = EncryptedTx::from_compact(buf, len);
        let decrypted_input = DecryptedTx::from_encrypted_tx(&encrypted_input);
        return (
            TxSeismic {
                encrypted_tx: Box::new(encrypted_input),
                decrypted_tx: Box::new(decrypted_input),
            },
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

impl TxSeismic {
    generate_decrypted_getters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Bytes
    );
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
    generate_decrypted_setters!(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        input: Bytes
    );
}

impl TxSeismic {
    pub fn new(
        chain_id: ChainId,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: TxKind,
        value: U256,
        encrypted_input: Vec<u8>,
    ) -> Self {
        let encrypted_tx = EncryptedTx {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input: encrypted_input.clone(),
        };
        let decrypted_tx = DecryptedTx::from_encrypted_tx(&encrypted_tx);
        TxSeismic { encrypted_tx: Box::new(encrypted_tx), decrypted_tx: Box::new(decrypted_tx) }
    }

    // functions imported from TxLegacy
    /// Calculates a heuristic for the in-memory size of the [`TxLegacy`] transaction.
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<Option<ChainId>>() + // chain_id
        mem::size_of::<u64>() + // nonce
        mem::size_of::<u128>() + // gas_price
        mem::size_of::<u64>() + // gas_limit
        self.to().size() + // to
        mem::size_of::<U256>() + // value
        self.input().len() // input
    }

    /// Outputs the length of the transaction's fields, without a RLP header or length of the
    /// eip155 fields.
    pub(crate) fn fields_len(&self) -> usize {
        self.nonce().length()
            + self.gas_price().length()
            + self.gas_limit().length()
            + self.to().length()
            + self.value().length()
            + self.input().length()
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header or
    /// eip155 fields.
    pub(crate) fn encode_fields(&self, out: &mut dyn bytes::BufMut) {
        self.nonce().encode(out);
        self.gas_price().encode(out);
        self.gas_limit().encode(out);
        self.to().encode(out);
        self.value().encode(out);
        self.input().encode(out);
    }

    /// Inner encoding function that is used for both rlp [`Encodable`] trait and for calculating
    /// hash.
    ///
    /// This encodes the transaction as:
    /// `rlp(nonce, gas_price, gas_limit, to, value, input, v, r, s)`
    ///
    /// The `v` value is encoded according to EIP-155 if the `chain_id` is not `None`.
    pub(crate) fn encode_with_signature(&self, signature: &Signature, out: &mut dyn bytes::BufMut) {
        let payload_length =
            self.fields_len() + signature.payload_len_with_eip155_chain_id(Some(*self.chain_id()));
        let header = Header { list: true, payload_length };
        header.encode(out);
        self.encode_fields(out);
        signature.encode_with_eip155_chain_id(out, Some(*self.chain_id()));
    }

    /// Output the length of the RLP signed transaction encoding.
    pub(crate) fn payload_len_with_signature(&self, signature: &Signature) -> usize {
        let payload_length =
            self.fields_len() + signature.payload_len_with_eip155_chain_id(Some(*self.chain_id()));
        // 'header length' + 'payload length'
        length_of_length(payload_length) + payload_length
    }

    /// Get transaction type
    pub(crate) const fn tx_type(&self) -> TxType {
        TxType::Legacy
    }

    /// Encodes EIP-155 arguments into the desired buffer. Only encodes values for legacy
    /// transactions.
    ///
    /// If a `chain_id` is `Some`, this encodes the `chain_id`, followed by two zeroes, as defined
    /// by [EIP-155](https://eips.ethereum.org/EIPS/eip-155).
    pub(crate) fn encode_eip155_fields(&self, out: &mut dyn bytes::BufMut) {
        self.chain_id().encode(out);
        0x00u8.encode(out);
        0x00u8.encode(out);
    }

    /// Outputs the length of EIP-155 fields. Only outputs a non-zero value for EIP-155 legacy
    /// transactions.
    pub(crate) fn eip155_fields_len(&self) -> usize {
        self.chain_id().length() + 2
    }

    /// Encodes the legacy transaction in RLP for signing, including the EIP-155 fields if possible.
    ///
    /// If a `chain_id` is `Some`, this encodes the transaction as:
    /// `rlp(nonce, gas_price, gas_limit, to, value, input, chain_id, 0, 0)`
    ///
    /// Otherwise, this encodes the transaction as:
    /// `rlp(nonce, gas_price, gas_limit, to, value, input)`
    pub(crate) fn encode_for_signing(&self, out: &mut dyn bytes::BufMut) {
        Header { list: true, payload_length: self.fields_len() + self.eip155_fields_len() }
            .encode(out);
        self.encode_fields(out);
        self.encode_eip155_fields(out);
    }

    /// Outputs the length of the signature RLP encoding for the transaction, including the length
    /// of the EIP-155 fields if possible.
    pub(crate) fn payload_len_for_signature(&self) -> usize {
        let payload_length = self.fields_len() + self.eip155_fields_len();
        // 'header length' + 'payload length'
        length_of_length(payload_length) + payload_length
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

// Seismic TODO put this into test module

pub fn aes_gcm_example() {
    let rng = AesRng::default();
    let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(rng);
    let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref()).unwrap();
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    assert_eq!(&plaintext, b"plaintext message");
    println!("AES-GCM Encrypted successfully: {:?}", ciphertext);
}

// #[test]
// fn test_from_seismictransactionsigned_to_transactionsigned() {
//     let encoded_tx_signed_plaintext = hex!("02f872018307910d808507204d2cb1827d0094388c818ca8b9251b393131c08a736a67ccb19297880320d04823e2701c80c001a0cf024f4815304df2867a1a74e9d2707b6abda0337d2d54a4438d453f4160f190a07ac0e6b3bc9395b5b9c8b9e6d77204a236577a5b18467b9175c01de4faa208d9");
//     let orig_tx_signed =
//         TxEip4844::decode(&mut &encoded_tx_signed_plaintext[..]).unwrap();

//     // encrypt it
//     let rng = AesRng::default();
//     let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);
//     let seismic_transaction =
//         TxSeismic::from_transaction(orig_tx_signed.clone());

//     assert_eq!(orig_tx_signed.nonce, seismic_transaction.nonce);

//     // decrypt it
//     let recovered_tx_signed = TxSeismic::decrypt(&seismic_transaction);
//     assert!(orig_tx_signed == recovered_tx_signed);
// }
