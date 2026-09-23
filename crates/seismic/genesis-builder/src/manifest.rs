use crate::{
    error::{BuilderError, Result},
    types::{Manifest, COMMIT_SHA_LEN},
};
use std::{fs, path::Path};

/// Load and parse the genesis contracts manifest from a TOML file
pub fn load_manifest(path: &Path) -> Result<Manifest> {
    if !path.exists() {
        return Err(BuilderError::ManifestNotFound(path.to_path_buf()));
    }

    parse_manifest(&fs::read_to_string(path)?)
}

/// Parse and validate the genesis contracts manifest from TOML text
pub fn parse_manifest(content: &str) -> Result<Manifest> {
    let manifest: Manifest = toml::from_str(content)?;

    validate_manifest(&manifest)?;

    Ok(manifest)
}

/// Validate the manifest structure
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    // Check if contracts exist
    if manifest.contracts.is_empty() {
        return Err(BuilderError::NoContractsDefined);
    }

    validate_ref(manifest)?;
    validate_addresses(manifest)?;

    Ok(())
}

/// Validate that the manifest pins its artifacts to a full commit SHA. A branch
/// name or an abbreviated SHA would leave a rebuild depending on whatever the
/// monorepo happens to hold when it runs.
fn validate_ref(manifest: &Manifest) -> Result<()> {
    let git_ref = &manifest.metadata.git_ref;

    if git_ref.len() != COMMIT_SHA_LEN || !git_ref.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BuilderError::InvalidRef(format!(
            "{git_ref}: expected a full {COMMIT_SHA_LEN}-character commit SHA"
        )));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_pinning(git_ref: &str) -> String {
        format!(
            r#"
            [metadata]
            version = "0.1.0"
            ref = "{git_ref}"

            [contracts.Registry]
            artifact = "artifacts/MeasurementRegistry.json"
            address = "0x1000000000000000000000000000000000000001"
            "#
        )
    }

    #[test]
    fn pinned_commit_builds_the_artifact_base_url() {
        let sha = "cadca3ccf0717a9199c612d0d2621d83161a7ae8";
        let manifest = parse_manifest(&manifest_pinning(sha)).unwrap();

        assert_eq!(
            manifest.metadata.base_url(),
            format!("https://raw.githubusercontent.com/SeismicSystems/seismic/{sha}/contracts")
        );
    }

    #[test]
    fn unpinned_refs_are_rejected() {
        for git_ref in ["main", "refs/heads/main", "cadca3c", "v1.0.0"] {
            let error = parse_manifest(&manifest_pinning(git_ref)).unwrap_err();

            assert!(
                matches!(error, BuilderError::InvalidRef(_)),
                "{git_ref} should not pass validation, got: {error}"
            );
        }
    }

    #[test]
    fn a_ref_is_required() {
        let unpinned = r#"
            [metadata]
            version = "0.1.0"

            [contracts.Registry]
            artifact = "artifacts/MeasurementRegistry.json"
            address = "0x1000000000000000000000000000000000000001"
        "#;

        assert!(matches!(parse_manifest(unpinned).unwrap_err(), BuilderError::Toml(_)));
    }
}
