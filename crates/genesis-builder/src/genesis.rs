use crate::{
    error::{BuilderError, Result},
    types::Genesis,
};
use std::{fs, path::Path};

/// Load genesis JSON file
pub fn load_genesis(path: &Path) -> Result<Genesis> {
    if !path.exists() {
        return Err(BuilderError::GenesisNotFound(path.to_path_buf()));
    }

    let content = fs::read_to_string(path)?;
    let genesis: Genesis = serde_json::from_str(&content)?;

    Ok(genesis)
}

/// Write genesis JSON file with pretty printing
pub fn write_genesis(genesis: &Genesis, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(genesis)?;
    fs::write(path, json)?;

    Ok(())
}
