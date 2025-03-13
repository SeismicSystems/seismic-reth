//! This crate provides functionalities related to the Enclave service.
//! It includes modules and API for interacting with wallet operations and HTTP clients.

use std::{
    future::Future,
    net::{IpAddr, TcpListener},
};

use derive_more::Display;
use secp256k1::PublicKey;
pub use seismic_enclave::{
    client::{
        rpc::BuildableServer, EnclaveClient, MockEnclaveServer, ENCLAVE_DEFAULT_ENDPOINT_ADDR,
        ENCLAVE_DEFAULT_ENDPOINT_PORT,
    },
    SchnorrkelKeypair,
};
use seismic_enclave::{
    nonce::Nonce,
    request_types::tx_io::{
        IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
    },
    rpc::EnclaveApiClient,
};
use tokio::runtime::{Handle, Runtime};
use tracing::error;

/// Custom error type for reth error handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum EnclaveError {
    /// enclave encryption fails
    EncryptionError,
    /// enclave decryption fails
    DecryptionError,
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

/// Blocking decrypt function call to contact EnclaveAPI
pub fn decrypt(
    enclave_client: &EnclaveClient,
    key: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<Vec<u8>, EnclaveError> {
    if data.len() == 0 {
        return Ok(data)
    }
    let payload = IoDecryptionRequest { key, data, nonce: Nonce::from(nonce) };
    let IoDecryptionResponse { decrypted_data } =
        block_on_with_runtime(enclave_client.decrypt(payload))
            .map_err(|_| EnclaveError::DecryptionError)?;
    Ok(decrypted_data)
}

/// Blocking encrypt function call to contact EnclaveAPI
pub fn encrypt(
    enclave_client: &EnclaveClient,
    key: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<Vec<u8>, EnclaveError> {
    if data.len() == 0 {
        return Ok(data)
    }
    let payload = IoEncryptionRequest { key, data, nonce: Nonce::from(nonce).into() };
    let IoEncryptionResponse { encrypted_data } =
        block_on_with_runtime(enclave_client.encrypt(payload))
            .map_err(|_| EnclaveError::DecryptionError)?;
    Ok(encrypted_data)
}

/// Blocking call to get the eph_rng_keypair, a SchnorrkelKeypair
pub fn get_eph_rng_keypair(
    enclave_client: &EnclaveClient,
) -> Result<SchnorrkelKeypair, EnclaveError> {
    let keypair = block_on_with_runtime(enclave_client.get_eph_rng_keypair())
        .map_err(|_| EnclaveError::EphRngKeypairGenerationError)?;

    Ok(keypair)
}

/// Get the test enclave endpoint
fn get_random_port() -> u16 {
    TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
        .expect("Failed to bind to a port")
        .local_addr()
        .unwrap()
        .port()
}

/// Start the mock enclave server
pub async fn start_mock_enclave_server_random_port() -> EnclaveClient {
    let port = get_random_port();
    tokio::spawn(async move {
        start_blocking_mock_enclave_server(ENCLAVE_DEFAULT_ENDPOINT_ADDR, port).await;
    });
    EnclaveClient::new_from_addr_port(ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string(), port)
}

/// Start the mock enclave server
pub async fn start_default_mock_enclave_server() -> EnclaveClient {
    let client = EnclaveClient::new_from_addr_port(
        ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string(),
        ENCLAVE_DEFAULT_ENDPOINT_PORT,
    );
    tokio::spawn(async move {
        start_blocking_mock_enclave_server(
            ENCLAVE_DEFAULT_ENDPOINT_ADDR,
            ENCLAVE_DEFAULT_ENDPOINT_PORT,
        )
        .await;
    });
    client
}

/// Start the mock enclave server
pub async fn start_blocking_mock_enclave_server(addr: IpAddr, port: u16) {
    let enclave_server = MockEnclaveServer::new((addr, port));

    let addr = enclave_server.addr();

    match enclave_server.start().await {
        Ok(handle) => {
            handle.stopped().await;
        }
        Err(err) => {
            let err = eyre::eyre!("Failed to start mock enclave server at {}: {}", addr, err);
            error!("{:?}", err);
        }
    }
}
