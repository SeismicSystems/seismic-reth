pub struct SeismicTransactionSigned {
    /// Transaction hash
    pub hash: TxHash,
    /// The transaction signature values
    pub signature: Signature,
    /// An encrypted version of the transaction info
    #[deref]
    #[as_ref]
    pub cipher_text: Bytes,
    // pub transaction: TxType, // This should include the seismic tranaction type
    pub nonce: u64,
}



use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key
};

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