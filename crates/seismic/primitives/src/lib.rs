//! Standalone crate for Optimism-specific Reth primitive types.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "alloy-compat")]
mod alloy_compat;

pub mod bedrock;

pub mod predeploys;
pub use predeploys::ADDRESS_L2_TO_L1_MESSAGE_PASSER;

pub mod transaction;
pub use transaction::{signed::SeismicTransactionSigned, tx_type::SeismicTxType};

mod receipt;
pub use receipt::SeismicReceipt;

/// Optimism-specific block type.
pub type SeismicBlock = alloy_consensus::Block<SeismicTransactionSigned>;

/// Optimism-specific block body type.
pub type SeismicBlockBody = <SeismicBlock as reth_primitives_traits::Block>::Body;

/// Primitive types for Optimism Node.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SeismicPrimitives;

impl reth_primitives_traits::NodePrimitives for SeismicPrimitives {
    type Block = SeismicBlock;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = SeismicBlockBody;
    type SignedTx = SeismicTransactionSigned;
    type Receipt = SeismicReceipt;
}

/// Bincode-compatible serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub mod serde_bincode_compat {
    pub use super::{
        receipt::serde_bincode_compat::*, transaction::signed::serde_bincode_compat::*,
    };
}
