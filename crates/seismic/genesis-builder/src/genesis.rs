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

/// Serialize a genesis to its canonical text form.
///
/// Committed genesis files are stored in this form, so rebuilding an unchanged
/// genesis is an empty diff and a contract bump is the only thing a reviewer
/// has to read. The form is:
///
/// - two-space-indented JSON with a single trailing newline;
/// - every object's keys alphabetically, with one deviation: `config` precedes `alloc` at the top
///   level, keeping the chain config at the head of the file rather than behind the allocations;
/// - `alloc` keyed by lowercase `0x` addresses in address order — since those keys are fixed-width
///   and lowercase, that is also their alphabetical order;
/// - per account `balance`, `code`, `nonce`, `storage`, absent fields omitted;
/// - hex strings kept verbatim: the manifest and the fetched artifacts are the sole source of their
///   spelling.
pub fn canonical_json(genesis: &Genesis) -> Result<String> {
    let mut json = serde_json::to_string_pretty(genesis)?;
    json.push('\n');

    Ok(json)
}

/// Write a genesis file in its [canonical form](canonical_json)
pub fn write_genesis(genesis: &Genesis, path: &Path) -> Result<()> {
    fs::write(path, canonical_json(genesis)?)?;

    Ok(())
}

/// Whether the genesis file at `path` already holds `genesis` verbatim, i.e.
/// whether [`write_genesis`] would leave it untouched
pub fn is_current(genesis: &Genesis, path: &Path) -> Result<bool> {
    Ok(fs::read_to_string(path)? == canonical_json(genesis)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genesis text exercising everything canonicalization has to fix: an
    /// uppercase alloc key, accounts and top-level fields out of order, a
    /// four-space indent, and no trailing newline.
    const SCRUFFY: &str = r#"{
    "alloc": {
        "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266": {
            "balance": "0x1"
        },
        "0x0000000000000000000000000000000000002001": {
            "storage": {
                "0x0000000000000000000000000000000000000000000000000000000000000001": "0x2",
                "0x0000000000000000000000000000000000000000000000000000000000000000": "0x1"
            },
            "code": "0x00",
            "balance": "0x0"
        }
    },
    "timestamp": "0x0",
    "config": {
        "chainId": 5124,
        "berlinBlock": 0
    },
    "gasLimit": "0x1c9c380"
}"#;

    const CANONICAL: &str = r#"{
  "config": {
    "berlinBlock": 0,
    "chainId": 5124
  },
  "alloc": {
    "0x0000000000000000000000000000000000002001": {
      "balance": "0x0",
      "code": "0x00",
      "storage": {
        "0x0000000000000000000000000000000000000000000000000000000000000000": "0x1",
        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x2"
      }
    },
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": {
      "balance": "0x1"
    }
  },
  "gasLimit": "0x1c9c380",
  "timestamp": "0x0"
}
"#;

    #[test]
    fn canonicalizes_key_case_order_and_layout() {
        let genesis: Genesis = serde_json::from_str(SCRUFFY).unwrap();

        assert_eq!(canonical_json(&genesis).unwrap(), CANONICAL);
    }

    #[test]
    fn canonical_form_is_a_fixed_point() {
        let genesis: Genesis = serde_json::from_str(CANONICAL).unwrap();

        assert_eq!(canonical_json(&genesis).unwrap(), CANONICAL);
    }
}
