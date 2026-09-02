//! Standalone crate for Seismic-specific Reth configuration and builder types.
//!
//! # features
//! - `js-tracer`: Enable the `JavaScript` tracer for the `debug_trace` endpoints

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
// #![cfg_attr(not(feature = "std"), no_std)]

pub mod engine;
pub mod keys_source;
pub mod node;
pub mod purpose_keys;
pub use reth_seismic_txpool as txpool;
pub mod utils;

pub use reth_seismic_payload_builder::SeismicPayloadBuilder;

pub use reth_seismic_evm::*;

use reth_chainspec::ChainSpec;
use std::sync::Arc;

/// Creates a Seismic EVM configuration with the given chain spec and purpose keys.
pub fn seismic_evm_config(
    spec: Arc<ChainSpec>,
    purpose_keys: &'static alloy_seismic_evm::PurposeKeys,
) -> SeismicEvmConfig {
    SeismicEvmConfig::new(spec, purpose_keys)
}
