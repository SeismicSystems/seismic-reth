use crate::error::{BuilderError, Result};
use crate::types::Manifest;
use std::fs;
use std::path::Path;

/// Load and parse the genesis contracts manifest from a TOML file
pub fn load_manifest(path: &Path) -> Result<Manifest> {
    if !path.exists() {
        return Err(BuilderError::ManifestNotFound(path.to_path_buf()));
    }

    let content = fs::read_to_string(path)?;
    let manifest: Manifest = toml::from_str(&content)?;

    validate_manifest(&manifest)?;

    Ok(manifest)
}

/// Validate the addresses in the manifest
fn validate_addresses(manifest: &Manifest) -> Result<()> {
    for (name, config) in &manifest.contracts {
        if !config.address.starts_with("0x") {
            return Err(BuilderError::InvalidAddress(format!(
                "{}: address must start with 0x",
                name
            )));
        }
    }
    Ok(())
}

/// Validate the manifest structure
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    // Check if contracts exist
    if manifest.contracts.is_empty() {
        return Err(BuilderError::NoContractsDefined);
    }

    validate_addresses(manifest)?;

    Ok(())
}