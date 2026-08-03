//! Pre-configured EVM factory and environment for fuzz targets.

use alloy_evm::EvmEnv;
use alloy_seismic_evm::SeismicEvmFactory;
use revm::context::CfgEnv;
use seismic_revm::SeismicSpecId;

use crate::{mock_keys::get_mock_keyring, mock_state::FUZZ_CHAIN_ID};

/// Creates a new `SeismicEvmFactory` with the shared mock keyring.
pub fn fuzz_evm_factory() -> SeismicEvmFactory {
    SeismicEvmFactory::new(get_mock_keyring())
}

/// MERCURY spec with [`FUZZ_CHAIN_ID`].
pub fn fuzz_evm_env() -> EvmEnv<SeismicSpecId> {
    EvmEnv {
        cfg_env: CfgEnv::new().with_chain_id(FUZZ_CHAIN_ID).with_spec(SeismicSpecId::MERCURY),
        ..Default::default()
    }
}
