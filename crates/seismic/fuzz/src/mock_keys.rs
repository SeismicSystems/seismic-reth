//! Mock purpose keys for fuzz targets.
use alloy_seismic_evm::{PurposeKeyring, PurposeKeys};
use std::sync::{Arc, OnceLock};

/// Returns a shared single-epoch keyring holding the mock purpose keys.
///
/// Safe for use in fuzz targets — the keyring is created once and reused across
/// all iterations within a single process.
pub fn get_mock_keyring() -> Arc<PurposeKeyring> {
    static KEYRING: OnceLock<Arc<PurposeKeyring>> = OnceLock::new();
    KEYRING
        .get_or_init(|| Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())))
        .clone()
}
