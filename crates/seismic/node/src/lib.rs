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

pub mod args;
pub mod engine;

pub mod node;

pub mod payload;

pub use reth_seismic_txpool as txpool;

pub mod utils;

pub use reth_seismic_payload_builder::SeismicPayloadBuilder;

pub use reth_seismic_evm::*;
