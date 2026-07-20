//! Mock purpose keys for fuzz targets.
use alloy_seismic_evm::PurposeKeys;
use seismic_crypto::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
};
use std::sync::OnceLock;

/// Returns a `&'static` reference to mock purpose keys.
///
/// Safe for use in fuzz targets — the allocation is leaked once and
/// reused across all iterations within a single process.
pub fn get_static_mock_keys() -> &'static PurposeKeys {
    static KEYS: OnceLock<&'static PurposeKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        Box::leak(Box::new(PurposeKeys {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            rng_ikm: get_unsecure_sample_schnorrkel_keypair().secret.to_bytes(),
        }))
    })
}
