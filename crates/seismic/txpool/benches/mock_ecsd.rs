//! Mock ECSD gRPC server for benchmarking.
//!
//! Responds instantly with empty `found` list to measure client-side overhead
//! (serialization, HTTP/2 framing, deserialization) without real Bloom filter latency.

use reth_seismic_txpool::screening::{ScreeningClient, ScreeningClientBuilder, ScreeningFailMode};
use std::time::Duration;

// Re-use the checked-in generated proto types
use reth_seismic_txpool::screening::proto::{
    ec_sd_server::{EcSd, EcSdServer},
    BatchCheckRequest, BatchCheckResponse, ExtendedHealthRequest, ExtendedHealthResponse,
};

/// Mock ECSD service that always returns no flagged addresses.
#[derive(Debug, Default)]
struct MockEcsd;

#[tonic::async_trait]
impl EcSd for MockEcsd {
    async fn batch_check_addresses(
        &self,
        request: tonic::Request<BatchCheckRequest>,
    ) -> Result<tonic::Response<BatchCheckResponse>, tonic::Status> {
        let req = request.into_inner();
        // All addresses are "not found" (not flagged)
        Ok(tonic::Response::new(BatchCheckResponse {
            found: vec![],
            not_found: req.addresses,
            found_count: 0,
            not_found_count: 0,
        }))
    }

    async fn health(
        &self,
        _request: tonic::Request<ExtendedHealthRequest>,
    ) -> Result<tonic::Response<ExtendedHealthResponse>, tonic::Status> {
        Ok(tonic::Response::new(ExtendedHealthResponse {
            status: 1,
            message: "OK".to_string(),
            filter: "mock".to_string(),
        }))
    }
}

/// Starts a mock ECSD gRPC server on a random port and returns a connected client.
pub async fn start_mock_ecsd_server() -> (ScreeningClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(EcSdServer::new(MockEcsd))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Brief delay for server startup
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = ScreeningClientBuilder::new(&format!("http://{addr}"))
        .timeout(Duration::from_secs(5))
        .fail_mode(ScreeningFailMode::Open)
        .build()
        .unwrap();

    (client, handle)
}
