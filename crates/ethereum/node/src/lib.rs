//! Standalone crate for ethereum-specific Reth configuration and builder types.
//!
//! # features
//! - `js-tracer`: Enable the `JavaScript` tracer for the `debug_trace` endpoints

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use reth_revm as _;
use revm as _;

pub use reth_ethereum_engine_primitives::EthEngineTypes;

pub mod evm;
pub use evm::{EthEvmConfig, EthExecutorProvider};

pub use reth_ethereum_consensus as consensus;
pub mod node;
pub use node::{EthereumEthApiBuilder, EthereumNode};

pub mod payload;

pub mod engine;
pub use engine::EthereumEngineValidator;
