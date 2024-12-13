//! This crate provides functionalities related to the Tee service.
//! It includes modules and API for interacting with wallet operations and HTTP clients.

/// Mock module for testing purposes.
pub mod mock;

pub use tee_service_api::{
    http_client::{TeeHttpClient, TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT},
    TeeAPI, WalletAPI,
};

use derive_more::Display;
use secp256k1::PublicKey;
use tee_service_api::request_types::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

/// Custom error type for reth error handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum TeeError {
    /// tee encryption fails
    EncryptionError,
    /// tee decryption fails
    DecryptionError,
    /// recover public key fails
    PublicKeyRecoveryError,
    /// encoding or decoding
    CodingError(alloy_rlp::Error),
    /// Custom error.
    Custom(&'static str),
}

/// Blocking decrypt function call to contact TeeAPI
pub fn decrypt<T: TeeAPI>(
    tee_client: &T,
    msg_sender: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<Vec<u8>, TeeError> {
    let payload = IoDecryptionRequest { msg_sender, data, nonce };
    let IoDecryptionResponse { decrypted_data } = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tee_client.tx_io_decrypt(payload))
    })
    .map_err(|_| TeeError::DecryptionError)?;
    Ok(decrypted_data)
}

/// Blocking encrypt function call to contact TeeAPI
pub fn encrypt<T: TeeAPI>(
    tee_client: &T,
    msg_sender: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<Vec<u8>, TeeError> {
    let payload = IoEncryptionRequest { msg_sender, data, nonce };

    let IoEncryptionResponse { encrypted_data } = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tee_client.tx_io_encrypt(payload))
    })
    .map_err(|_| TeeError::DecryptionError)?;
    Ok(encrypted_data)
}
