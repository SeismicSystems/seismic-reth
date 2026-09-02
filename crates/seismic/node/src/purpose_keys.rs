//! Global storage for purpose keys obtained on boot.
//!
//! This module provides thread-safe access to purpose keys that are fetched once
//! during node startup and then used throughout the application lifetime.
//!
//! ## Preferred path: structural injection
//!
//! Purpose keys should be injected into [`SeismicNode::new`](crate::node::SeismicNode::new),
//! which stores them and threads them through the node builder lifecycle
//! (executor builder, etc.). This avoids reliance on global state.
//!
//! ## Deprecated fallback: global `OnceLock`
//!
//! The global [`init_purpose_keys`] / [`get_purpose_keys`] functions are retained
//! as a fallback for code paths that cannot yet receive keys structurally (e.g.
//! the CLI `stage` command, or tests that construct `SeismicNode::default()`).
//! New code should prefer the injection path.

use alloy_seismic_evm::PurposeKeys;
use std::sync::OnceLock;

/// Global storage for purpose keys.
/// These keys are obtained once during node startup (see [`crate::keys_source`]).
static PURPOSE_KEYS: OnceLock<PurposeKeys> = OnceLock::new();

/// Initialize the global purpose keys.
/// This should be called once during node startup, after the purpose keys are obtained.
///
/// # Panics
/// Panics if called more than once.
#[allow(clippy::expect_used)] // Documented panic behavior
pub fn init_purpose_keys(keys: PurposeKeys) {
    PURPOSE_KEYS.set(keys).expect("Purpose keys already initialized");
}

/// Get a reference to the purpose keys.
///
/// # Panics
/// Panics if the keys haven't been initialized yet.
#[allow(clippy::expect_used)] // Documented panic behavior
pub fn get_purpose_keys() -> &'static PurposeKeys {
    PURPOSE_KEYS.get().expect("Purpose keys not initialized")
}

/// Leak-box the given keys onto the heap and return a `&'static` reference.
///
/// This is used by [`SeismicNode::new`](crate::node::SeismicNode::new) so that
/// the purpose keys have a `'static` lifetime without relying on the global
/// `OnceLock`.
pub fn leak_purpose_keys(keys: PurposeKeys) -> &'static PurposeKeys {
    Box::leak(Box::new(keys))
}
