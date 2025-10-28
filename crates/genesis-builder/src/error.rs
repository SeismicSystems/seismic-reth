use std::path::PathBuf;
use thiserror::Error;
use toml::de::Error as TomlError;

/// Errors that can occur during genesis building
#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("Manifest not found: {0}")]
    /// Manifest not found
    ManifestNotFound(PathBuf),
    /// No contracts defined in manifest
    #[error("No contracts defined in manifest")]
    NoContractsDefined,
    /// Genesis file not found
    #[error("Genesis file not found: {0}")]
    GenesisNotFound(PathBuf),
    /// Invalid address format
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
    /// Contract bytecode missing or empty
    #[error("Contract bytecode missing or empty: {0}")]
    MissingBytecode(String),
    /// Address collision between contracts
    #[error("Address collision: {0} already exists in genesis")]
    AddressCollision(String),
    /// Failed to fetch artifact from remote source
    #[error("Failed to fetch artifact from {0}: {1}")]
    RemoteFetchFailed(String, String),
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parse error
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// TOML parse error
    #[error("TOML parse error: {0}")]
    Toml(#[from] TomlError),
}

/// Result type for genesis builder operations
pub type Result<T> = std::result::Result<T, BuilderError>;