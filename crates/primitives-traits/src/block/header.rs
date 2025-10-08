//! Block header data primitive.

use crate::{InMemorySize, MaybeCompact, MaybeSerde, MaybeSerdeBincodeCompat};
use alloy_primitives::Sealable;
use core::{fmt, hash::Hash};

/// Re-exported alias
pub use alloy_consensus::BlockHeader as AlloyBlockHeader;

/// Helper trait that unifies all behaviour required by block header to support full node
/// operations.
pub trait FullBlockHeader: BlockHeader + MaybeCompact {}

impl<T> FullBlockHeader for T where T: BlockHeader + MaybeCompact {}

/// Abstraction of a block header.
pub trait BlockHeader:
    Send
    + Sync
    + Unpin
    + Clone
    + Hash
    + Default
    + fmt::Debug
    + PartialEq
    + Eq
    + alloy_rlp::Encodable
    + alloy_rlp::Decodable
    + alloy_consensus::BlockHeader
    + Sealable
    + InMemorySize
    + MaybeSerde
    + MaybeSerdeBincodeCompat
    + AsRef<Self>
    + 'static
{
    /// Returns the timestamp in seconds, assuming the timestamp is in milliseconds.
    fn timestamp_seconds(&self) -> u64 {
        if cfg!(feature = "timestamp-in-seconds") {
            self.timestamp()
        } else {
            self.timestamp() / 1000
        }
    }
}

impl BlockHeader for alloy_consensus::Header {}
