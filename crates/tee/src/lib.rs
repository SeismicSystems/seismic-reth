//! This crate provides functionalities related to the Tee service.
//! It includes modules and API for interacting with wallet operations and HTTP clients.

use std::future::Future;

use derive_more::Display;
use secp256k1::PublicKey;
use seismic_enclave::{
    nonce::Nonce,
    request_types::tx_io::{
        IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
    },
};
use tokio::runtime::{Handle, Runtime};

/// Custom error type for reth error handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum TeeError {
    /// tee encryption fails
    EncryptionError,
    /// tee decryption fails
    DecryptionError,
    /// recover public key fails
    PublicKeyRecoveryError,
    /// Ephemereal keypair generation fails
    EphRngKeypairGenerationError,
    /// encoding or decoding
    CodingError(alloy_rlp::Error),
    /// Custom error.
    Custom(&'static str),
}

/// A wrapper function that runs a future to completion.
/// It uses the current Tokio runtime if available; otherwise, it creates a new one.
pub fn block_on_with_runtime<F, T>(future: F) -> T
where
    F: Future<Output = T>,
{
    tokio::task::block_in_place(|| {
        match Handle::try_current() {
            Ok(handle) => {
                // Runtime exists, use it
                handle.block_on(future)
            }
            Err(_) => {
                // No runtime, create a new one
                let runtime = Runtime::new().expect("Failed to create a Tokio runtime");
                runtime.block_on(future)
            }
        }
    })
}

/// Blocking decrypt function call to contact TeeAPI
pub fn decrypt<T: TeeAPI>(
    tee_client: &T,
    key: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<Vec<u8>, TeeError> {
    if data.len() == 0 {
        return Ok(data)
    }
    let payload = IoDecryptionRequest { key, data, nonce: Nonce::from(nonce) };
    let IoDecryptionResponse { decrypted_data } =
        block_on_with_runtime(tee_client.tx_io_decrypt(payload))
            .map_err(|_| TeeError::DecryptionError)?;
    Ok(decrypted_data)
}

/// Blocking encrypt function call to contact TeeAPI
pub fn encrypt<T: TeeAPI>(
    tee_client: &T,
    key: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<Vec<u8>, TeeError> {
    if data.len() == 0 {
        return Ok(data)
    }
    let payload = IoEncryptionRequest { key, data, nonce: Nonce::from(nonce).into() };
    let IoEncryptionResponse { encrypted_data } =
        block_on_with_runtime(tee_client.tx_io_encrypt(payload))
            .map_err(|_| TeeError::DecryptionError)?;
    Ok(encrypted_data)
}

/// Blocking call to get the eph_rng_keypair, a SchnorrkelKeypair
pub fn get_eph_rng_keypair<T: TeeAPI>(tee_client: &T) -> Result<SchnorrkelKeypair, TeeError> {
    let keypair = block_on_with_runtime(tee_client.get_eph_rng_keypair())
        .map_err(|_| TeeError::EphRngKeypairGenerationError)?;

    Ok(keypair)
}
