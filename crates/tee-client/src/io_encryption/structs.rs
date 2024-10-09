use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoEncryptionRequest {
    pub msg_sender: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

// Struct for serializing the response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoEncryptionResponse {
    pub encrypted_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoDecryptionRequest {
    pub msg_sender: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

// Struct for serializing the response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoDecryptionResponse {
    pub decrypted_data: Vec<u8>,
}
