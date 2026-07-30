//! Protocol constants and storage decoding for the `KeyRotationRegistry` predeploy.
//!
//! # Lockstep warning
//!
//! Everything in this module mirrors the (not yet shipped) `KeyRotationRegistry.sol`
//! in the contracts repo: the predeploy address, the storage layout, the entry
//! packing, and the event signature. The contract is the source of truth — if it
//! lands with a different shape, this module (and its decode fixtures, which are the
//! lockstep anchor) must change with it in the same manifest-`ref` bump.
//!
//! Assumed contract storage layout (design spec §3.1):
//!
//! ```solidity
//! address admin;                 // slot 0
//! Rotation[] rotations;          // slot 1 (length), elements at keccak256(1) + i
//! struct Rotation {
//!     uint64 epoch;              // bits 0..64 of the packed word
//!     uint64 activationBlock;    // bits 64..128
//!     uint64 announcedAtBlock;   // bits 128..192
//! }
//! event RotationAnnounced(uint64 indexed epoch, uint64 activationBlock);
//! ```

use crate::schedule::RotationEntry;
use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use std::sync::LazyLock;
use thiserror::Error;

/// The `KeyRotationRegistry` predeploy address.
///
/// Next free slot in the `0x1000…000N` predeploy family: `…0001`/`…0002` are the
/// measurement registry/authority, `…0004`/`…0005` are Directory/Intelligence,
/// `…0006` is the ops whitelist-tx sentinel, and `…0003` is retired. Must match the
/// future `manifest.toml` entry.
pub const KEY_ROTATION_REGISTRY: Address = address!("1000000000000000000000000000000000000007");

/// Storage slot of the registry's admin address.
pub const ADMIN_SLOT: B256 = B256::ZERO;

/// Storage slot holding the rotations array length.
pub const ROTATIONS_LEN_SLOT: B256 =
    b256!("0000000000000000000000000000000000000000000000000000000000000001");

/// `topic0` of `RotationAnnounced(uint64,uint64)` — the watcher's low-latency hint
/// (storage stays the source of truth).
pub static ROTATION_ANNOUNCED_TOPIC: LazyLock<B256> =
    LazyLock::new(|| keccak256("RotationAnnounced(uint64,uint64)"));

/// The storage slot of rotations array element `index`
/// (Solidity dynamic array: `keccak256(len_slot) + index`).
pub fn rotation_entry_slot(index: u64) -> B256 {
    let base = U256::from_be_bytes(keccak256(ROTATIONS_LEN_SLOT).0);
    B256::from(base.wrapping_add(U256::from(index)))
}

/// A rotations array element failed to decode.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryDecodeError {
    /// The word's upper 64 bits are not zero — not a packed `Rotation`.
    #[error("rotation entry {index}: upper 64 bits of the storage word are not zero")]
    Malformed {
        /// Array index of the offending entry.
        index: u64,
    },
    /// The entry's stored epoch is not `index + 1` (epochs are dense).
    #[error("rotation entry {index} declares epoch {got}, expected {expected}")]
    EpochMismatch {
        /// Array index of the offending entry.
        index: u64,
        /// The epoch the entry carries.
        got: u64,
        /// The dense epoch required at this index.
        expected: u64,
    },
}

/// Decodes a rotations array element read from storage, validating the packing and
/// the dense-epoch invariant (`entry i` is epoch `i + 1`).
pub fn decode_rotation_entry(word: B256, index: u64) -> Result<RotationEntry, RegistryDecodeError> {
    let value = U256::from_be_bytes(word.0);
    // U256 limbs are little-endian u64s: limb 0 is the low-order 64 bits, matching
    // Solidity's packing of the first declared struct field.
    let [epoch, activation_block, announced_at_block, padding] = *value.as_limbs();
    if padding != 0 {
        return Err(RegistryDecodeError::Malformed { index });
    }
    let expected = index.checked_add(1).ok_or(RegistryDecodeError::Malformed { index })?;
    if epoch != expected {
        return Err(RegistryDecodeError::EpochMismatch { index, got: epoch, expected });
    }
    Ok(RotationEntry { epoch, activation_block, announced_at_block })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // test code

    use super::*;

    /// `keccak256(uint256(1))` — the well-known base slot of a dynamic array at
    /// slot 1. Independent fixture so the slot derivation can't silently drift.
    const ARRAY_BASE: B256 =
        b256!("b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6");

    #[test]
    fn entry_slots_derive_from_the_known_array_base() {
        assert_eq!(rotation_entry_slot(0), ARRAY_BASE);
        let mut plus_one = ARRAY_BASE;
        *plus_one.0.last_mut().unwrap() += 1; // ...f6 -> ...f7, no carry
        assert_eq!(rotation_entry_slot(1), plus_one);
    }

    /// Big-endian hex fixture decoded against the limb-order logic: epoch 1 in the
    /// low-order bytes, activation 0xC8 (200) next, announcement 0x64 (100) above it.
    #[test]
    fn decodes_solidity_packed_entry() {
        let word = b256!("0000000000000000000000000000006400000000000000c80000000000000001");
        assert_eq!(
            decode_rotation_entry(word, 0),
            Ok(RotationEntry { epoch: 1, activation_block: 200, announced_at_block: 100 })
        );
    }

    #[test]
    fn rejects_nonzero_padding() {
        let word = b256!("0100000000000000000000000000006400000000000000c80000000000000001");
        assert_eq!(
            decode_rotation_entry(word, 0),
            Err(RegistryDecodeError::Malformed { index: 0 })
        );
    }

    #[test]
    fn rejects_non_dense_epoch() {
        let word = b256!("0000000000000000000000000000006400000000000000c80000000000000001");
        assert_eq!(
            decode_rotation_entry(word, 1),
            Err(RegistryDecodeError::EpochMismatch { index: 1, got: 1, expected: 2 })
        );
    }

    #[test]
    fn topic_is_stable() {
        // Pins the event-signature string; recomputed here so an accidental edit to
        // either constant shows up as a diff.
        assert_eq!(*ROTATION_ANNOUNCED_TOPIC, keccak256("RotationAnnounced(uint64,uint64)"));
    }
}
