//! Seismic meta crate that provides access to commonly used reth dependencies.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unused_crate_dependencies)]

/// Re-exported ethereum types
#[doc(inline)]
pub use reth_seismic_primitives::*;

/// Re-exported reth primitives
pub mod primitives {
    #[doc(inline)]
    pub use reth_primitives_traits::*;
}

/// Re-exported cli types
#[cfg(feature = "cli")]
pub use reth_seismic_cli as cli;

/// Re-exported from `reth_chainspec`
pub mod chainspec {
    #[doc(inline)]
    pub use reth_chainspec::*;
}

/// Re-exported evm types
#[cfg(feature = "evm")]
pub mod evm {
    #[doc(inline)]
    pub use reth_seismic_evm::*;

    #[doc(inline)]
    pub use reth_evm as primitives;
}

/// Re-exported reth network types
#[cfg(feature = "network")]
pub mod network {
    #[doc(inline)]
    pub use reth_network::*;
}

/// Re-exported reth provider types
#[cfg(feature = "provider")]
pub mod provider {
    #[doc(inline)]
    pub use reth_provider::*;

    #[doc(inline)]
    pub use reth_db as db;
}

/// Re-exported reth storage api types
#[cfg(feature = "storage-api")]
pub mod storage {
    #[doc(inline)]
    pub use reth_storage_api::*;
}

/// Re-exported ethereum node
#[cfg(feature = "node-api")]
pub mod node {
    #[doc(inline)]
    pub use reth_node_api as api;
    #[cfg(feature = "node")]
    pub use reth_seismic_node::*;
}

/// Re-exported reth trie types
#[cfg(feature = "trie")]
pub mod trie {
    #[doc(inline)]
    pub use reth_trie::*;
}

/// Re-exported rpc types
#[cfg(feature = "rpc")]
pub mod rpc {
    #[doc(inline)]
    pub use reth_rpc::*;
    #[doc(inline)]
    pub use reth_seismic_rpc::*;

    #[doc(inline)]
    pub use reth_rpc_api as api;
    #[doc(inline)]
    pub use reth_rpc_builder as builder;
    #[doc(inline)]
    pub use reth_rpc_eth_types as eth;
}
