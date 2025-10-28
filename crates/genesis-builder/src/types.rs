use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default base URL for the manifest which will be
/// used if a base URL is not provided explicitly
pub const DEFAULT_BASE_URL: &str =
    "https://raw.githubusercontent.com/seismic/seismic-contracts/main";

/// Contract configuration from manifest
#[derive(Debug, Deserialize, Clone)]
pub struct ContractConfig {
    /// Relative path to the artifact file
    pub artifact: String,
    /// Address where the contract will be deployed
    pub address: String,
}

/// Full manifest structure
#[derive(Debug, Deserialize)]
pub struct Manifest {
    /// Metadata in `manifest.toml`
    pub metadata: ManifestMetadata,
    /// Contracts to deploy
    pub contracts: HashMap<String, ContractConfig>,
}

#[derive(Debug, Deserialize)]
/// Metadata in `manifest.toml`
pub struct ManifestMetadata {
    /// Version of the manifest
    pub version: String,
    /// Description of the manifest
    pub description: Option<String>,
    /// Base GitHub URL for all artifacts
    /// If not provided, the default base URL will be used
    pub base_url: Option<String>,
}

impl ManifestMetadata {
    /// Get the base URL for the manifest
    pub fn base_url(&self) -> &str {
        self.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL)
    }
}

/// Contract artifact from JSON
#[derive(Debug)]
pub struct ContractArtifact {
    /// Name of the contract
    pub name: String,
    /// Bytecode of the contract
    pub bytecode: Bytes,
}

/// Genesis file structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Genesis {
    /// Configuration of the genesis file
    pub config: serde_json::Value,
    /// Allocations of the genesis file
    pub alloc: HashMap<Address, GenesisAccount>,
    /// Other fields of the genesis file
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Account in the genesis file
pub struct GenesisAccount {
    /// Code of the account
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Balance of the account
    pub balance: String,
    /// Nonce of the account
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Storage of the account
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub storage: HashMap<String, String>,
}
