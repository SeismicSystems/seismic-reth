//! Seismic's payload builder implementation.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(clippy::useless_let_if_seq)]

pub mod builder;
pub use builder::SeismicPayloadBuilder;

pub use reth_ethereum_payload_builder::EthereumBuilderConfig as SeismicBuilderConfig;

// Use reth_ethereum_primitives to suppress unused import warning
// We import the crate ensure features such as serde and reth-codec are enabled
// When it is pulled in by other dependencies
use reth_ethereum_primitives as _;
