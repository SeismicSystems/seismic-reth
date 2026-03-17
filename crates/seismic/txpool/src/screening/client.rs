//! gRPC client for the ECSD (Ethereum Compliance Screening Daemon) sidecar.
//!
//! Connects to ECSD and screens batches of addresses via `BatchCheckAddresses`.
//! Supports configurable fail-open/fail-closed behavior when the sidecar is unavailable.

use std::{fmt, str::FromStr, sync::Arc, time::Duration};

use super::proto::{ec_sd_client::EcSdClient, BatchCheckRequest, BatchCheckResponse};

/// Behavior when the ECSD sidecar is unreachable or returns an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScreeningFailMode {
    /// Transactions pass through when ECSD is unavailable (permissive).
    #[default]
    Open,
    /// Transactions are rejected when ECSD is unavailable (restrictive).
    Closed,
}

impl FromStr for ScreeningFailMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "invalid screening fail mode: {other:?}, expected \"open\" or \"closed\""
            )),
        }
    }
}

impl fmt::Display for ScreeningFailMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Error type for screening operations.
#[derive(Debug, derive_more::Display)]
pub enum ScreeningError {
    /// The ECSD sidecar is unreachable or returned a gRPC error.
    #[display("screening sidecar error: {_0}")]
    SidecarError(String),
    /// Failed to build the gRPC channel.
    #[display("screening client build error: {_0}")]
    BuildError(String),
}

impl std::error::Error for ScreeningError {}

/// Client for communicating with the ECSD address screening sidecar.
///
/// Wraps a tonic gRPC channel with fail-mode handling and request timeout.
/// The underlying HTTP/2 connection is persistent and multiplexed.
#[derive(Clone)]
pub struct ScreeningClient {
    inner: Arc<ScreeningClientInner>,
}

struct ScreeningClientInner {
    client: tokio::sync::Mutex<EcSdClient<tonic::transport::Channel>>,
    fail_mode: ScreeningFailMode,
    timeout: Duration,
}

impl fmt::Debug for ScreeningClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScreeningClient")
            .field("fail_mode", &self.inner.fail_mode)
            .field("timeout", &self.inner.timeout)
            .finish()
    }
}

impl ScreeningClient {
    /// Screens a batch of addresses via ECSD `BatchCheckAddresses`.
    ///
    /// Returns the list of flagged (found-in-blocklist) addresses.
    ///
    /// On sidecar errors:
    /// - **Fail-open**: returns `Ok(vec![])` (transaction passes through)
    /// - **Fail-closed**: returns `Err` (transaction is rejected)
    pub async fn screen_addresses(
        &self,
        addresses: Vec<String>,
    ) -> Result<Vec<String>, ScreeningError> {
        let request = tonic::Request::new(BatchCheckRequest { addresses, hops: None });

        let result: Result<
            Result<tonic::Response<BatchCheckResponse>, tonic::Status>,
            tokio::time::error::Elapsed,
        > = {
            let mut client = self.inner.client.lock().await;
            tokio::time::timeout(self.inner.timeout, client.batch_check_addresses(request)).await
        };

        match result {
            Ok(Ok(response)) => Ok(response.into_inner().found),
            Ok(Err(status)) => self.handle_error(status.to_string()),
            Err(_elapsed) => self.handle_error("request timed out".to_string()),
        }
    }

    /// Handles a sidecar error according to the configured fail mode.
    fn handle_error(&self, error: String) -> Result<Vec<String>, ScreeningError> {
        match self.inner.fail_mode {
            ScreeningFailMode::Open => {
                tracing::warn!(
                    target: "txpool::screening",
                    %error,
                    "ECSD sidecar error (fail-open, allowing transaction)"
                );
                Ok(vec![])
            }
            ScreeningFailMode::Closed => Err(ScreeningError::SidecarError(error)),
        }
    }
}

/// Builder for [`ScreeningClient`].
///
/// Uses `connect_lazy()` so the node starts even if ECSD isn't ready yet.
/// The gRPC connection is established on the first request.
#[derive(Debug)]
pub struct ScreeningClientBuilder {
    endpoint: String,
    timeout: Duration,
    fail_mode: ScreeningFailMode,
}

impl ScreeningClientBuilder {
    /// Creates a new builder with the given ECSD endpoint.
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            timeout: Duration::from_millis(100),
            fail_mode: ScreeningFailMode::Open,
        }
    }

    /// Sets the request timeout.
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the fail mode.
    pub const fn fail_mode(mut self, fail_mode: ScreeningFailMode) -> Self {
        self.fail_mode = fail_mode;
        self
    }

    /// Builds the [`ScreeningClient`].
    ///
    /// Uses `connect_lazy()` — no blocking at startup. The connection is
    /// established on the first RPC call and then reused (HTTP/2 multiplexing).
    pub fn build(self) -> Result<ScreeningClient, ScreeningError> {
        let channel = tonic::transport::Channel::from_shared(self.endpoint)
            .map_err(|e| ScreeningError::BuildError(e.to_string()))?
            .connect_lazy();

        let client = EcSdClient::new(channel);

        Ok(ScreeningClient {
            inner: Arc::new(ScreeningClientInner {
                client: tokio::sync::Mutex::new(client),
                fail_mode: self.fail_mode,
                timeout: self.timeout,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_mode_from_str() {
        assert_eq!(ScreeningFailMode::from_str("open").unwrap(), ScreeningFailMode::Open);
        assert_eq!(ScreeningFailMode::from_str("closed").unwrap(), ScreeningFailMode::Closed);
        assert_eq!(ScreeningFailMode::from_str("Open").unwrap(), ScreeningFailMode::Open);
        assert_eq!(ScreeningFailMode::from_str("CLOSED").unwrap(), ScreeningFailMode::Closed);
        assert!(ScreeningFailMode::from_str("invalid").is_err());
    }

    #[test]
    fn builder_defaults() {
        let builder = ScreeningClientBuilder::new("http://127.0.0.1:9090");
        assert_eq!(builder.timeout, Duration::from_millis(100));
        assert_eq!(builder.fail_mode, ScreeningFailMode::Open);
        assert_eq!(builder.endpoint, "http://127.0.0.1:9090");
    }

    #[tokio::test]
    async fn builder_constructs_client() {
        let client = ScreeningClientBuilder::new("http://127.0.0.1:9090")
            .timeout(Duration::from_secs(5))
            .fail_mode(ScreeningFailMode::Closed)
            .build();
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn fail_open_returns_empty_on_unreachable() {
        let client = ScreeningClientBuilder::new("http://127.0.0.1:19999")
            .timeout(Duration::from_millis(50))
            .fail_mode(ScreeningFailMode::Open)
            .build()
            .unwrap();

        let result = client.screen_addresses(vec!["0xdead".to_string()]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fail_closed_returns_error_on_unreachable() {
        let client = ScreeningClientBuilder::new("http://127.0.0.1:19999")
            .timeout(Duration::from_millis(50))
            .fail_mode(ScreeningFailMode::Closed)
            .build()
            .unwrap();

        let result = client.screen_addresses(vec!["0xdead".to_string()]).await;
        assert!(result.is_err());
    }
}
