//! Mock purpose keys for fuzz targets.
use alloy_seismic_evm::{PurposeKeyring, PurposeKeys};
use seismic_crypto::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
};
use std::sync::{Arc, OnceLock};

/// Returns a shared single-epoch keyring holding the mock purpose keys.
///
/// Safe for use in fuzz targets — the keyring is created once and reused across
/// all iterations within a single process.
pub fn get_mock_keyring() -> Arc<PurposeKeyring> {
    static KEYRING: OnceLock<Arc<PurposeKeyring>> = OnceLock::new();
    KEYRING
        .get_or_init(|| {
            Arc::new(PurposeKeyring::single_epoch(PurposeKeys {
                tx_io_sk: get_unsecure_sample_secp256k1_sk(),
                tx_io_pk: get_unsecure_sample_secp256k1_pk(),
                rng_ikm: get_unsecure_sample_schnorrkel_keypair().secret.to_bytes(),
            }))
        })
        .clone()
}
