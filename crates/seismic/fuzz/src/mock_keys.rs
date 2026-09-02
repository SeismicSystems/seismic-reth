//! Mock purpose keys for fuzz targets.
use alloy_seismic_evm::PurposeKeys;
use std::sync::OnceLock;

/// Returns a `&'static` reference to mock purpose keys.
///
/// Safe for use in fuzz targets — the allocation is leaked once and
/// reused across all iterations within a single process.
pub fn get_static_mock_keys() -> &'static PurposeKeys {
    static KEYS: OnceLock<&'static PurposeKeys> = OnceLock::new();
    KEYS.get_or_init(|| Box::leak(Box::new(PurposeKeys::well_known())))
}
