//! Mock purpose keys for fuzz targets.
//!
//! Uses `Box::leak` to satisfy the `&'static` lifetime requirement of
//! `SeismicEvmFactory::new_with_purpose_keys`. The allocation is leaked once
//! via `OnceLock` and reused across all fuzz iterations.

use seismic_enclave::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk, GetPurposeKeysResponse,
};
use std::sync::OnceLock;

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
