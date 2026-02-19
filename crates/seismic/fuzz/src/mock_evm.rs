//! Pre-configured EVM factory and environment for fuzz targets.

use alloy_evm::EvmEnv;
use alloy_seismic_evm::SeismicEvmFactory;
use revm::context::CfgEnv;
use seismic_revm::SeismicSpecId;

use crate::mock_keys::get_static_mock_keys;

/// Seismic EVM factory configured with mock purpose keys.
pub fn fuzz_evm_factory() -> SeismicEvmFactory {
    SeismicEvmFactory::new_with_purpose_keys(get_static_mock_keys())
}

/// Chain ID 5123, MERCURY spec.
pub fn fuzz_evm_env() -> EvmEnv<SeismicSpecId> {
    EvmEnv {
        cfg_env: CfgEnv::new().with_chain_id(5123).with_spec(SeismicSpecId::MERCURY),
        ..Default::default()
    }
}
