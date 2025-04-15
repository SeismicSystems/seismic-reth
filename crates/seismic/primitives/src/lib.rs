//! Standalone crate for Seismic-specific Reth primitive types.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod transaction;
use seismic_alloy_consensus::SeismicTxEnvelope;

mod receipt;
pub use receipt::SeismicReceipt;

/// Seismic-specific block type.
pub type SeismicBlock = alloy_consensus::Block<SeismicTxEnvelope>;

/// Seismic-specific block body type.
pub type SeismicBlockBody = <SeismicBlock as reth_primitives_traits::Block>::Body;

/// Primitive types for Optimism Node.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SeismicPrimitives;

impl reth_primitives_traits::NodePrimitives for SeismicPrimitives {
    type Block = SeismicBlock;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = SeismicBlockBody;
    type SignedTx = SeismicTxEnvelope;
    type Receipt = SeismicReceipt;
}

/// Bincode-compatible serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub mod serde_bincode_compat {
    pub use super::{
        receipt::serde_bincode_compat::*, transaction::signed::serde_bincode_compat::*,
    };
}
