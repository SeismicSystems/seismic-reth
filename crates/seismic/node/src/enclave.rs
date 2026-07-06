//! Tools to communicate with the seismic-enclave-server's RPC
use std::{net::SocketAddr, time::Duration};

use jsonrpsee_http_client::{HttpClient, HttpClientBuilder};
use reth_node_core::args::EnclaveArgs;
use seismic_enclave::{
    api::TdxQuoteRpcClient as _, mock::start_mock_server, GetPurposeKeysResponse,
};
use tracing::{info, warn};

/// Builds the enclave JSON-RPC client, binding each request to the configured `enclave_timeout`.
#[allow(clippy::expect_used)] // Intentional panic on startup failure - enclave is required
fn build_enclave_client(config: &EnclaveArgs) -> HttpClient {
    HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(config.enclave_timeout))
        .build(format!("http://{}:{}", config.enclave_server_addr, config.enclave_server_port))
        .expect("Failed to build enclave client")
}

/// Boot the enclave (or mock server) and fetch purpose keys.
/// This must be called before building the node components.
/// Panics if the enclave cannot be booted or purpose keys cannot be fetched.
///
/// Total fetch attempts = `config.retries` + 1 (one initial attempt plus `retries`
/// re-attempts); the `while failures <= config.retries` loop encodes this directly.
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
    let enclave_client = build_enclave_client(config);

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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // Test code - expect on failure is acceptable

    use super::*;
    use std::time::Instant;
    use tokio::net::TcpListener;

    /// A stalled enclave endpoint (accepts connections but never replies) must make the fetch
    /// error within the configured `enclave_timeout`, not hang on the underlying client default.
    #[tokio::test]
    async fn enclave_timeout_bounds_a_stalled_fetch() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            // The Vec exists only to keep the sockets alive; it is never read.
            #[allow(clippy::collection_is_never_read)]
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // keep the connection open without ever responding
            }
        });

        let config = EnclaveArgs {
            enclave_server_addr: addr.ip(),
            enclave_server_port: addr.port(),
            enclave_timeout: 1,
            ..Default::default()
        };
        let client = build_enclave_client(&config);

        let started = Instant::now();
        let result = client.get_purpose_keys(0).await;

        assert!(result.is_err(), "stalled fetch should error, not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "fetch should be bounded by enclave_timeout, took {:?}",
            started.elapsed()
        );
    }
}
