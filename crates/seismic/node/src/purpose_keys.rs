//! Global storage for purpose keys fetched from enclave on boot.
//!
//! This module provides thread-safe access to purpose keys that are fetched once
//! during node startup and then used throughout the application lifetime.

use seismic_enclave::keys::GetPurposeKeysResponse;
use std::sync::OnceLock;

/// Global storage for purpose keys.
/// These keys are fetched once from the enclave during node startup.
static PURPOSE_KEYS: OnceLock<GetPurposeKeysResponse> = OnceLock::new();

/// Initialize the global purpose keys.
/// This should be called once during node startup, after the enclave is booted.
///
/// # Panics
/// Panics if called more than once.
pub fn init_purpose_keys(keys: GetPurposeKeysResponse) {
    PURPOSE_KEYS.set(keys).expect("Purpose keys already initialized");
}

/// Get a reference to the purpose keys.
///
/// # Panics
/// Panics if the keys haven't been initialized yet.
pub fn get_purpose_keys() -> &'static GetPurposeKeysResponse {
    PURPOSE_KEYS.get().expect("Purpose keys not initialized")
}

/// Get the RNG keypair from the purpose keys.
pub fn get_rng_keypair() -> &'static schnorrkel::Keypair {
    &get_purpose_keys().rng_keypair
}

/// Get the transaction I/O public key from the purpose keys.
pub fn get_tx_io_pk() -> &'static secp256k1::PublicKey {
    &get_purpose_keys().tx_io_pk
}

/// Get the transaction I/O secret key from the purpose keys.
pub fn get_tx_io_sk() -> &'static secp256k1::SecretKey {
    &get_purpose_keys().tx_io_sk
}
