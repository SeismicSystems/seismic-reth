//! Genesis builder for constructing genesis files with contracts
//!
//! Two layers, separable by consumers that only need one of them:
//!
//! - editing ([`genesis`], [`types`]): parse a genesis file, edit its allocations, write the
//!   canonical form back out.
//! - fetching ([`artifact`], [`builder`]): resolve a manifest's contracts against the artifacts of
//!   the commit it pins and allocate them in a genesis.

/// Artifact loader for fetching contract artifacts
pub mod artifact;
/// Genesis builder for constructing genesis files
pub mod builder;
/// Error types
pub mod error;
/// Genesis file handling
pub mod genesis;
/// Manifest file handling
pub mod manifest;
/// Common types
pub mod types;

pub use builder::GenesisBuilder;
pub use error::{BuilderError, Result};
pub use genesis::{canonical_json, load_genesis, write_genesis};
pub use manifest::load_manifest;
pub use types::{ContractConfig, Genesis, GenesisAccount, Manifest, ManifestMetadata};
