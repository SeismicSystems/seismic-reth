use crate::{
    error::{BuilderError, Result},
    types::ContractArtifact,
};
use alloy_primitives::{hex, Bytes};
use serde_json::Value;
use std::time::Duration;
use tracing::info;

/// Default timeout for loading contract artifacts from remote
pub const DEFAULT_ARTIFACT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client for loading contract artifacts
#[derive(Debug, Clone)]
pub struct ArtifactLoader {
    /// HTTP client
    client: reqwest::blocking::Client,
}

impl ArtifactLoader {
    /// Create a new artifact loader with default settings
    pub fn new() -> Result<Self> {
        Self::with_timeout(DEFAULT_ARTIFACT_TIMEOUT)
    }

    /// Create a new artifact loader with custom timeout
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let client =
            reqwest::blocking::Client::builder().timeout(timeout).build().map_err(|e| {
                BuilderError::RemoteFetchFailed("client initialization".to_string(), e.to_string())
            })?;

        Ok(Self { client })
    }

    /// Load contract artifact from a remote URL
    pub fn load_artifact(&self, url: &str) -> Result<ContractArtifact> {
        info!("Fetching {}", url);

        let data = self.fetch_remote(url)?;

        let json: Value = serde_json::from_slice(&data)?;

        let bytecode = Self::extract_bytecode(&json, url)?;

        let name = Self::extract_name(&json, url);

        Ok(ContractArtifact { name, bytecode })
    }

    /// Fetch artifact from GitHub via HTTP
    fn fetch_remote(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|e| BuilderError::RemoteFetchFailed(url.to_string(), e.to_string()))?;

        let data = response
            .bytes()
            .map_err(|e| BuilderError::RemoteFetchFailed(url.to_string(), e.to_string()))?
            .to_vec();

        Ok(data)
    }

    /// Extract bytecode from artifact JSON
    fn extract_bytecode(json: &Value, url: &str) -> Result<Bytes> {
        if let Some(deployed) = json.get("deployedBytecode") {
            if let Some(hex) = deployed.get("object").and_then(|o| o.as_str()) {
                return Self::parse_hex_bytecode(hex, url);
            }
        }

        Err(BuilderError::MissingBytecode(url.to_string()))
    }

    /// Parse hex string into bytecode
    fn parse_hex_bytecode(hex: &str, url: &str) -> Result<Bytes> {
        hex::decode(hex)
            .map(Bytes::from)
            .map_err(|_| BuilderError::InvalidHex(format!("Invalid hex in bytecode: {}", url)))
    }

    /// Extract contract name from artifact JSON or URL
    fn extract_name(json: &Value, url: &str) -> String {
        if let Some(name) = json.get("contractName").and_then(|n| n.as_str()) {
            return name.to_string();
        }

        // Fallback to filename from URL
        url.split('/').last().and_then(|s| s.strip_suffix(".json")).unwrap_or("unknown").to_string()
    }
}
