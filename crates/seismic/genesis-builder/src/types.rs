use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Raw-content base of the `SeismicSystems/seismic` monorepo, which holds the
/// compiled artifacts of the contracts a manifest allocates
pub const ARTIFACT_REPO_RAW_URL: &str = "https://raw.githubusercontent.com/SeismicSystems/seismic";

/// Directory holding the compiled artifacts inside the monorepo
pub const ARTIFACT_REPO_CONTRACTS_DIR: &str = "contracts";

/// Length of the commit SHA a manifest pins
pub const COMMIT_SHA_LEN: usize = 40;

/// Contract configuration from manifest
#[derive(Debug, Deserialize, Clone)]
pub struct ContractConfig {
    /// Relative path to the artifact file
    pub artifact: String,
    /// Address where the contract will be deployed
    pub address: String,
    /// Optional balance for the contract (defaults to "0x0")
    pub balance: Option<String>,
    /// Optional nonce for the contract
    pub nonce: Option<String>,
    /// Optional storage to initialize at the contract address
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
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
    /// Full commit SHA of the monorepo whose artifacts this manifest allocates.
    /// Pinning a commit is what makes a rebuild reproducible: bumping contracts
    /// is a one-line SHA change, reviewed next to the regenerated genesis.
    #[serde(rename = "ref")]
    pub git_ref: String,
}

impl ManifestMetadata {
    /// Base URL of the artifacts pinned by [`Self::git_ref`]
    pub fn base_url(&self) -> String {
        format!("{ARTIFACT_REPO_RAW_URL}/{}/{ARTIFACT_REPO_CONTRACTS_DIR}", self.git_ref)
    }
}

/// Contract artifact from JSON
#[derive(Debug)]
pub struct ContractArtifact {
    /// Name of the contract
    pub name: String,
    /// Bytecode of the contract
    pub deployed_bytecode: Bytes,
}

/// Genesis file structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Genesis {
    /// Configuration of the genesis file
    pub config: serde_json::Value,
    /// Allocations of the genesis file
    pub alloc: BTreeMap<Address, GenesisAccount>,
    /// Other fields of the genesis file
    #[serde(flatten)]
    pub other: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Account in the genesis file
pub struct GenesisAccount {
    /// Balance of the account
    pub balance: String,
    /// Code of the account
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Nonce of the account
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Storage of the account
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage: BTreeMap<String, String>,
}
