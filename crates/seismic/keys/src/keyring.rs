//! The epoch-keyed purpose keyring: rotation schedule plus per-epoch key material.

use crate::schedule::{RotationSchedule, ScheduleError};
use alloy_seismic_evm::PurposeKeys;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use thiserror::Error;

/// The keyring has no key material for an epoch it was asked to serve.
///
/// For consensus consumers this must be a hard failure with no fallback: executing
/// with another epoch's keys forks the state root (wrong `rng_ikm`) or flips
/// `decryption_failed` receipts (wrong `tx_io_sk`).
#[derive(Debug, Error, PartialEq, Eq)]
#[error("purpose keys for epoch {epoch} are not in the keyring (needed for block {block}); waiting on a custodian fetch")]
pub struct MissingEpochKeys {
    /// The epoch whose keys are missing.
    pub epoch: u64,
    /// The block that needed them.
    pub block: u64,
}

/// An epoch already holds key material that differs from a new insertion — the
/// custodian derivation is deterministic, so this can only be a bug.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("epoch {epoch} already holds different purpose keys")]
pub struct EpochKeyConflict {
    /// The conflicting epoch.
    pub epoch: u64,
}

struct KeyringState {
    schedule: RotationSchedule,
    /// Epoch -> keys. Never evicted: old epochs decrypt historical transactions and
    /// reproduce historical RNG outputs during sync.
    keys: BTreeMap<u64, PurposeKeys>,
    /// The highest canonical tip this keyring has been told about (monotonic).
    /// Drives [`PurposeKeyring::current`] and [`PurposeKeyring::pending`].
    known_tip: u64,
}

/// Shared, swappable purpose-key state: the rotation schedule and the key material
/// for every known epoch. Cheap to clone behind an `Arc`; all methods take `&self`.
///
/// Today the block executor still receives a `&'static PurposeKeys` pinned to
/// epoch 0 (the `alloy-seismic-evm` factories have not adopted the keyring yet — see
/// `docs/design/purpose-key-rotation.md` §5.1); the keyring is the source the rest of
/// the node reads through so that adoption is a plumbing change, not a redesign.
pub struct PurposeKeyring {
    inner: RwLock<KeyringState>,
}

impl fmt::Debug for PurposeKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.read();
        // Deliberately omits the key material.
        f.debug_struct("PurposeKeyring")
            .field("schedule", &state.schedule)
            .field("epochs_with_keys", &state.keys.keys().collect::<Vec<_>>())
            .field("known_tip", &state.known_tip)
            .finish()
    }
}

impl PurposeKeyring {
    /// A keyring holding only epoch 0 with an empty schedule — the pre-rotation
    /// state every node boots with, and the whole story for dev nodes and tests.
    pub fn single_epoch(keys: PurposeKeys) -> Self {
        Self {
            inner: RwLock::new(KeyringState {
                schedule: RotationSchedule::new(),
                keys: BTreeMap::from([(0, keys)]),
                known_tip: 0,
            }),
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, KeyringState> {
        self.inner.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, KeyringState> {
        self.inner.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The epoch active for `block` per the known schedule (0 while no rotation is
    /// announced).
    pub fn epoch_for_block(&self, block: u64) -> u64 {
        self.read().schedule.epoch_at_block(block)
    }

    /// The keys for the epoch active at `block`. Hard error when the epoch's keys
    /// have not been fetched — callers must never substitute another epoch.
    pub fn keys_for_block(&self, block: u64) -> Result<PurposeKeys, MissingEpochKeys> {
        let state = self.read();
        let epoch = state.schedule.epoch_at_block(block);
        state.keys.get(&epoch).cloned().ok_or(MissingEpochKeys { epoch, block })
    }

    /// The epoch and keys active at the last known canonical tip. This is what RPC
    /// advertises (`seismic_getTeePublicKey`) and decrypts signed reads with.
    pub fn current(&self) -> Result<(u64, PurposeKeys), MissingEpochKeys> {
        let state = self.read();
        let epoch = state.schedule.epoch_at_block(state.known_tip);
        state
            .keys
            .get(&epoch)
            .cloned()
            .map(|keys| (epoch, keys))
            .ok_or(MissingEpochKeys { epoch, block: state.known_tip })
    }

    /// The soonest announced-but-not-yet-activated rotation as of the known tip, as
    /// `(epoch, activation_block)`. Drives the pool's expiry boundary rule.
    pub fn pending(&self) -> Option<(u64, u64)> {
        let state = self.read();
        state
            .schedule
            .pending_after(state.known_tip)
            .map(|entry| (entry.epoch, entry.activation_block))
    }

    /// Records a canonical tip observation (monotonic max).
    pub fn note_tip(&self, tip: u64) {
        let mut state = self.write();
        if tip > state.known_tip {
            state.known_tip = tip;
        }
    }

    /// The highest canonical tip this keyring has been told about.
    pub fn known_tip(&self) -> u64 {
        self.read().known_tip
    }

    /// Inserts key material for an epoch. Idempotent: re-inserting identical keys
    /// returns `Ok(false)`; inserting *different* keys for a known epoch is a bug
    /// and errors without overwriting.
    pub fn insert_epoch(&self, epoch: u64, keys: PurposeKeys) -> Result<bool, EpochKeyConflict> {
        let mut state = self.write();
        match state.keys.get(&epoch) {
            Some(existing) if keys_equal(existing, &keys) => Ok(false),
            Some(_) => Err(EpochKeyConflict { epoch }),
            None => {
                state.keys.insert(epoch, keys);
                Ok(true)
            }
        }
    }

    /// Extends the schedule to match a newer read of the registry (append-only
    /// merge). Returns the number of newly learned rotations.
    pub fn apply_schedule(&self, newer: &RotationSchedule) -> Result<usize, ScheduleError> {
        self.write().schedule.extend_to(newer)
    }

    /// Number of rotations in the known schedule.
    pub fn schedule_len(&self) -> usize {
        self.read().schedule.len()
    }

    /// The keys for a specific epoch, if fetched.
    pub fn keys_for_epoch(&self, epoch: u64) -> Option<PurposeKeys> {
        self.read().keys.get(&epoch).cloned()
    }

    /// Scheduled epochs (1..=schedule len) whose keys are not yet in the keyring —
    /// the watcher's fetch work-list and the value of the
    /// `pending_unfetched_epochs` metric. Epoch 0 is excluded (seeded at boot).
    pub fn unfetched_scheduled_epochs(&self) -> Vec<u64> {
        let state = self.read();
        (1..=state.schedule.len() as u64).filter(|epoch| !state.keys.contains_key(epoch)).collect()
    }
}

/// Field-wise equality; `PurposeKeys` does not derive `PartialEq` itself.
fn keys_equal(a: &PurposeKeys, b: &PurposeKeys) -> bool {
    a.tx_io_sk == b.tx_io_sk && a.tx_io_pk == b.tx_io_pk && a.rng_ikm == b.rng_ikm
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // test code

    use super::*;
    use crate::schedule::{RotationEntry, RotationSchedule};
    use alloy_seismic_evm::secp256k1::{Secp256k1, SecretKey};

    fn test_keys(seed: u8) -> PurposeKeys {
        let sk = SecretKey::from_byte_array(&[seed; 32]).unwrap();
        let pk = sk.public_key(&Secp256k1::new());
        PurposeKeys { tx_io_sk: sk, tx_io_pk: pk, rng_ikm: [seed; 64] }
    }

    fn schedule(entries: &[(u64, u64, u64)]) -> RotationSchedule {
        RotationSchedule::from_entries(entries.iter().map(|&(epoch, activation, announced)| {
            RotationEntry { epoch, activation_block: activation, announced_at_block: announced }
        }))
        .unwrap()
    }

    #[test]
    fn single_epoch_serves_epoch_zero_everywhere() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        assert_eq!(keyring.epoch_for_block(0), 0);
        assert_eq!(keyring.epoch_for_block(u64::MAX), 0);
        assert_eq!(keyring.keys_for_block(12345).unwrap().rng_ikm, [1; 64]);
        let (epoch, keys) = keyring.current().unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(keys.rng_ikm, [1; 64]);
        assert_eq!(keyring.pending(), None);
        assert!(keyring.unfetched_scheduled_epochs().is_empty());
    }

    #[test]
    fn missing_epoch_is_a_hard_error() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        keyring.apply_schedule(&schedule(&[(1, 100, 10)])).unwrap();
        assert_eq!(keyring.keys_for_block(99).unwrap().rng_ikm, [1; 64]);
        assert_eq!(
            keyring.keys_for_block(100).map(|_| ()),
            Err(MissingEpochKeys { epoch: 1, block: 100 })
        );
        assert_eq!(keyring.unfetched_scheduled_epochs(), vec![1]);
    }

    #[test]
    fn fetched_epoch_serves_from_activation() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        keyring.apply_schedule(&schedule(&[(1, 100, 10)])).unwrap();
        assert!(keyring.insert_epoch(1, test_keys(2)).unwrap());
        assert_eq!(keyring.keys_for_block(99).unwrap().rng_ikm, [1; 64]);
        assert_eq!(keyring.keys_for_block(100).unwrap().rng_ikm, [2; 64]);
        assert!(keyring.unfetched_scheduled_epochs().is_empty());
    }

    #[test]
    fn insert_is_idempotent_and_conflicts_error() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        assert!(keyring.insert_epoch(1, test_keys(2)).unwrap());
        assert!(!keyring.insert_epoch(1, test_keys(2)).unwrap());
        assert_eq!(keyring.insert_epoch(1, test_keys(3)), Err(EpochKeyConflict { epoch: 1 }));
        // The original material survives a conflicting insert.
        assert_eq!(keyring.keys_for_epoch(1).unwrap().rng_ikm, [2; 64]);
    }

    #[test]
    fn current_and_pending_follow_the_noted_tip() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        keyring.apply_schedule(&schedule(&[(1, 100, 10)])).unwrap();
        keyring.insert_epoch(1, test_keys(2)).unwrap();

        keyring.note_tip(50);
        assert_eq!(keyring.current().unwrap().0, 0);
        assert_eq!(keyring.pending(), Some((1, 100)));

        keyring.note_tip(100);
        assert_eq!(keyring.current().unwrap().0, 1);
        assert_eq!(keyring.pending(), None);

        // Tips are monotonic: a stale observation cannot roll the epoch back.
        keyring.note_tip(10);
        assert_eq!(keyring.current().unwrap().0, 1);
    }
}
