//! Shared `KeyRotationRegistry` protocol constants and storage decoding.
//!
//! The implementation lives with the block executor so consensus execution and
//! the canonical watcher decode exactly the same parent-state storage layout.
pub use alloy_seismic_evm::registry::*;
