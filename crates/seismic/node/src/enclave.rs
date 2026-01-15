//! Tools to communicate with the seismic-enclave-server's RPC
use std::net::SocketAddr;

use jsonrpsee_http_client::HttpClientBuilder;
use reth_node_core::args::EnclaveArgs;
use seismic_enclave::{
    api::TdxQuoteRpcClient as _, mock::start_mock_server, GetPurposeKeysResponse,
};
use tracing::{info, warn};

/// Boot the enclave (or mock server) and fetch purpose keys.
/// This must be called before building the node components.
/// Panics if the enclave cannot be booted or purpose keys cannot be fetched.
#[allow(clippy::expect_used)] // Intentional panic on startup failure - enclave is required
#[allow(clippy::panic)] // Intentional panic on fetching keys failure - enclave keys are required
pub async fn boot_enclave_and_fetch_keys<T>(config: &T) -> GetPurposeKeysResponse
where
    T: AsRef<EnclaveArgs>,
{
    let config = config.as_ref();
    // Boot enclave or start mock server
    if config.mock_server {
        info!(target: "reth::cli", "Starting mock enclave server");
        let addr = config.enclave_server_addr;
        let port = config.enclave_server_port;
        tokio::spawn(async move {
            start_mock_server(SocketAddr::new(addr, port))
                .await
                .expect("Failed to start mock enclave server");
        });
        // Give the mock server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    let enclave_client = HttpClientBuilder::default()
        .build(format!("http://{}:{}", config.enclave_server_addr, config.enclave_server_port))
        .expect("Failed to build enclave client");

    // Fetch purpose keys from enclave - this must succeed or we panic
    info!(target: "reth::cli", "Fetching purpose keys from enclave");
    let mut failures = 0;
    while failures <= config.retries {
        match enclave_client.get_purpose_keys(0).await {
            Ok(purpose_keys) => {
                info!(target: "reth::cli", "Successfully fetched purpose keys from enclave");
                return purpose_keys;
            }
            Err(e) => {
                warn!(target: "reth::cli", "Failure to fetch purpose keys {}/{}: {}", failures, config.retries, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(config.retry_seconds.into()))
                    .await;
                failures += 1;
            }
        }
    }
    panic!("FATAL: Failed to fetch purpose keys from enclave on boot after {} failures", failures);
}
