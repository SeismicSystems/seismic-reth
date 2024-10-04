use super::signature::Signature;
use crate::transaction::TransactionSigned;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key,
};
use alloy_primitives::TxHash;
use alloy_rlp::{Decodable, Encodable};
use bytes::Bytes;
use revm_primitives::hex;

pub struct SeismicTransactionSigned {
    /// Transaction hash
    pub hash: TxHash,
    /// The transaction signature values
    pub signature: Signature,
    /// encrypted bytes for a vanilla TransactionSigned
    pub ciphertext: Vec<u8>,
    // pub transaction: TxType, // This should include the seismic tranaction type
    pub nonce: u64,
}

impl SeismicTransactionSigned {}

impl SeismicTransactionSigned {
    pub fn decrypt(&self, key: Key<Aes256Gcm>) -> TransactionSigned {
        let cipher = Aes256Gcm::new(&key);
        let nonce = SeismicTransactionSigned::nonce_to_generic_array(self.nonce);
        /// bytes for a vanilla TransactionSigned in plaintext
        let mut plaintext = cipher.decrypt(&nonce, self.ciphertext.as_ref()).unwrap();
        TransactionSigned::decode(&mut plaintext.as_slice())
            .expect("SeismicTransactionSigned: unable to decode plaintext into TransactionSigned")
    }

    pub fn from_transaction_signed(tx: TransactionSigned, key: Key<Aes256Gcm>) -> Self {
        let mut out = Vec::new();
        tx.encode(&mut out);

        let cipher = Aes256Gcm::new(&key);
        let nonce = SeismicTransactionSigned::nonce_to_generic_array(tx.transaction.nonce());
        let ciphertext = cipher.encrypt(&nonce, out.as_ref()).unwrap();
        SeismicTransactionSigned {
            hash: tx.hash(),
            signature: tx.signature().clone(),
            ciphertext: ciphertext,
            nonce: tx.transaction.nonce(),
        }
    }

    pub fn nonce_to_generic_array(
        nonce: u64,
    ) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
        let mut nonce_bytes = nonce.to_be_bytes().to_vec();


        let crypto_nonce_size =  GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();

       nonce_bytes.resize(crypto_nonce_size, 0); // pad for crypto

        let rng = AesRng::default();
        let libnonce = Aes256Gcm::generate_nonce(rng);
        println!("libnonce {:?}", libnonce.len());

        GenericArray::clone_from_slice(&nonce_bytes)

    }
}

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

#[test]
fn test_from_seismictransactionsigned_to_transactionsigned() {
    let encoded_tx_signed_plaintext = hex!("02f872018307910d808507204d2cb1827d0094388c818ca8b9251b393131c08a736a67ccb19297880320d04823e2701c80c001a0cf024f4815304df2867a1a74e9d2707b6abda0337d2d54a4438d453f4160f190a07ac0e6b3bc9395b5b9c8b9e6d77204a236577a5b18467b9175c01de4faa208d9");
    let orig_tx_signed =
        TransactionSigned::decode_enveloped(&mut &encoded_tx_signed_plaintext[..]).unwrap();

    // encrypt it
    let rng = AesRng::default();
    let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);
    let seismic_transaction =
        SeismicTransactionSigned::from_transaction_signed(orig_tx_signed.clone(), key);

    assert_eq!(orig_tx_signed.transaction.nonce(), seismic_transaction.nonce);

    // decrypt it
    let recovered_tx_signed = SeismicTransactionSigned::decrypt(&seismic_transaction, key);
    assert!(orig_tx_signed == recovered_tx_signed);
}
