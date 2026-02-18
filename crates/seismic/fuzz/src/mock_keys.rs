//! Mock purpose keys for fuzz targets.
//!
//! Provides deterministic, static purpose keys using the same unsecure sample
//! keys used by the test infrastructure. These keys are leaked via `Box::leak`
//! to satisfy the `'static` lifetime requirement of `SeismicEvmConfig::new`.

use seismic_enclave::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk, GetPurposeKeysResponse,
};
use std::sync::OnceLock;

/// Returns a `&'static` reference to mock purpose keys.
///
/// Safe for use in fuzz targets — the allocation is leaked once and
/// reused across all iterations within a single process.
pub fn get_static_mock_keys() -> &'static GetPurposeKeysResponse {
    static KEYS: OnceLock<&'static GetPurposeKeysResponse> = OnceLock::new();
    KEYS.get_or_init(|| {
        Box::leak(Box::new(GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        }))
    })
}
