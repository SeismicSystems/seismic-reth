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