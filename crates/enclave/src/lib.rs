//! This crate provides functionalities related to the Enclave service.
//! It includes modules and API for interacting with wallet operations and HTTP clients.

use std::net::{IpAddr, TcpListener};

use derive_more::Display;
pub use seismic_enclave::{
    client::{
        rpc::{BuildableServer, SyncEnclaveApiClient},
        EnclaveClient, MockEnclaveServer, ENCLAVE_DEFAULT_ENDPOINT_ADDR,
        ENCLAVE_DEFAULT_ENDPOINT_PORT,
    },
    SchnorrkelKeypair,
};
use tracing::error;

/// Custom error type for reth error handling.
#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum EnclaveError {
    /// enclave encryption fails
    EncryptionError,
    /// enclave decryption fails
    DecryptionError,
    /// Ephemereal keypair generation fails
    EphRngKeypairGenerationError(String),
    /// Custom error.
    Custom(&'static str),
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
    EnclaveClient::builder().addr(ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string()).port(port).build()
}

/// Start the mock enclave server
pub async fn start_default_mock_enclave_server() -> EnclaveClient {
    let client = EnclaveClient::builder()
        .addr(ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string())
        .port(ENCLAVE_DEFAULT_ENDPOINT_PORT)
        .build();
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
