//! This crate provides functionalities related to the Tee service.
//! It includes modules and API for interacting with wallet operations and HTTP clients.

/// Mock module for testing purposes.
pub mod mock;

pub use tee_service_api::{
    http_client::{TeeHttpClient, TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT},
    TeeAPI, WalletAPI,
};

use alloy_rlp::{Decodable, Encodable};
use derive_more::Display;
use secp256k1::PublicKey;
use tee_service_api::request_types::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

/// Custom error type for reth error handling.
#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum TeeError {
    /// tee encryption fails
    EncryptionError,
    /// tee decryption fails
    DecryptionError(String),
    /// recover public key fails
    PublicKeyRecoveryError,
    /// encoding or decoding
    CodingError(alloy_rlp::Error),
    /// Custom error.
    Custom(&'static str),
}

/// Blocking decrypt function call to contact TeeAPI
pub fn decrypt<I: Encodable + Decodable, T: TeeAPI>(
    tee_client: &T,
    msg_sender: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<I, TeeError> {
    let payload = IoDecryptionRequest { msg_sender, data, nonce };
    println!("Decryption payload: {:?}", payload);
    let IoDecryptionResponse { decrypted_data } = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tee_client.tx_io_decrypt(payload))
    })
    .map_err(|e| TeeError::DecryptionError(e.to_string()))?;
    I::decode(&mut &decrypted_data[..]).map_err(|err| TeeError::CodingError(err))
}

/// Blocking encrypt function call to contact TeeAPI
pub fn encrypt<I: Encodable + Decodable, T: TeeAPI>(
    tee_client: &T,
    msg_sender: PublicKey,
    plaintext: I,
    nonce: u64,
) -> Result<Vec<u8>, TeeError> {
    let mut data = Vec::new();
    plaintext.encode(&mut data);
    let payload = IoEncryptionRequest { msg_sender, data, nonce };

    let IoEncryptionResponse { encrypted_data } = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tee_client.tx_io_encrypt(payload))
    })
    .map_err(|e| TeeError::DecryptionError(e.to_string()))?;
    Ok(encrypted_data)
}
