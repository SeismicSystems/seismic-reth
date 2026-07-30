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

use alloy_seismic_evm::PurposeKeys;
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

/// Leak the keyring's epoch-0 keys onto the heap and return a `&'static` reference.
///
/// This is the temporary bridge to [`SeismicEvmConfig::new`](reth_seismic_evm::SeismicEvmConfig),
/// whose `alloy-seismic-evm` factories still take `&'static PurposeKeys`: the block
/// executor stays pinned to epoch 0 until those factories adopt the keyring (see
/// `docs/design/purpose-key-rotation.md` §5.1, rollout Phase 2). Each call leaks one
/// copy, exactly like the pre-keyring plumbing did; calls are bounded by node
/// constructions per process.
///
/// # Panics
/// Panics if the keyring has no epoch-0 keys; every keyring constructor seeds them.
#[allow(clippy::expect_used)] // Documented panic behavior
pub fn epoch0_static(keyring: &PurposeKeyring) -> &'static PurposeKeys {
    Box::leak(Box::new(
        keyring.keys_for_epoch(0).expect("keyring is always seeded with epoch-0 keys"),
    ))
}
