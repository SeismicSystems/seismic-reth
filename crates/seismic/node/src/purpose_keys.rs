//! Global storage for the purpose keyring obtained on boot.
//!
//! This module provides thread-safe access to the [`PurposeKeyring`] that is seeded
//! during node startup and shared throughout the application lifetime.
//!
//! ## Preferred path: structural injection
//!
//! The keyring should be injected into [`SeismicNode::new`](crate::node::SeismicNode::new),
//! which stores it and threads it through the node builder lifecycle
//! (executor builder, pool builder, etc.). This avoids reliance on global state.
//!
//! ## Deprecated fallback: global `OnceLock`
//!
//! The global [`init_purpose_keyring`] / [`get_purpose_keyring`] functions are
//! retained as a fallback for code paths that cannot yet receive the keyring
//! structurally (the CLI `stage` command, the RPC add-ons launch, and tests that
//! construct `SeismicNode::default()`). New code should prefer the injection path.

use reth_seismic_keys::PurposeKeyring;
use std::sync::{Arc, OnceLock};

/// Global storage for the purpose keyring.
/// Seeded once during node startup (see [`crate::keys_source`]).
static PURPOSE_KEYRING: OnceLock<Arc<PurposeKeyring>> = OnceLock::new();

/// Initialize the global purpose keyring.
/// This should be called once during node startup, after the epoch-0 purpose keys
/// are obtained.
///
/// # Panics
/// Panics if called more than once.
#[allow(clippy::expect_used)] // Documented panic behavior
pub fn init_purpose_keyring(keyring: Arc<PurposeKeyring>) {
    PURPOSE_KEYRING.set(keyring).expect("Purpose keyring already initialized");
}

/// Get a handle to the global purpose keyring.
///
/// # Panics
/// Panics if the keyring hasn't been initialized yet.
#[allow(clippy::expect_used)] // Documented panic behavior
pub fn get_purpose_keyring() -> Arc<PurposeKeyring> {
    PURPOSE_KEYRING.get().expect("Purpose keyring not initialized").clone()
}
