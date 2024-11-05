use serde::{Deserialize, Serialize};

/// Struct for serializing the request
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoEncryptionRequest {
    /// The public key of the message sender
    pub msg_sender: secp256k1::PublicKey,
    /// The data to be encrypted
    pub data: Vec<u8>,
    /// The nonce
    pub nonce: u64,
}

/// Struct for serializing the response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoEncryptionResponse {
    /// The encrypted data
    pub encrypted_data: Vec<u8>,
}

/// Struct for serializing the request
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoDecryptionRequest {
    /// The public key of the message sender
    pub msg_sender: secp256k1::PublicKey,
    /// The encrypted data
    pub data: Vec<u8>,
    /// The nonce
    pub nonce: u64,
}

/// Struct for serializing the response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoDecryptionResponse {
    /// The decrypted data
    pub decrypted_data: Vec<u8>,
}
