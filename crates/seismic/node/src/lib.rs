//! Standalone crate for Optimism-specific Reth configuration and builder types.
//!
//! # features
//! - `js-tracer`: Enable the `JavaScript` tracer for the `debug_trace` endpoints

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// CLI argument parsing for the optimism node.
pub mod args;

/// Exports optimism-specific implementations of the [`EngineTypes`](reth_node_api::EngineTypes)
/// trait.
pub mod engine;
pub use engine::SeismicEngineTypes;

pub mod node;
pub use node::{SeismicNetworkPrimitives, SeismicNode};

pub mod rpc;
pub use rpc::SeismicEngineApiBuilder;

pub mod version;
pub use version::OP_NAME_CLIENT;

pub use reth_seismic_txpool as txpool;

/// Helpers for running test node instances.
#[cfg(feature = "test-utils")]
pub mod utils;

pub use reth_seismic_payload_builder::{
    OpBuiltPayload, PayloadAttributes, SeismicPayloadBuilder, OpPayloadBuilderAttributes,
};

pub use reth_seismic_evm::*;
