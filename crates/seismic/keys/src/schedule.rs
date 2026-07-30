//! The validated, append-only history of key-rotation announcements.

use thiserror::Error;

/// One announced key rotation — the node-side mirror of a `KeyRotationRegistry`
/// storage entry (see `docs/design/purpose-key-rotation.md` §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationEntry {
    /// The epoch this rotation activates. Entry `i` of the registry array is always
    /// epoch `i + 1` (epoch 0 is the genesis epoch and never appears on-chain).
    pub epoch: u64,
    /// The first block executed with this epoch's keys.
    pub activation_block: u64,
    /// The block at which the rotation was announced on-chain. Always strictly less
    /// than `activation_block` (the contract enforces a minimum delay).
    pub announced_at_block: u64,
}

/// Errors validating or extending a [`RotationSchedule`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScheduleError {
    /// An entry's epoch is not the next dense epoch.
    #[error("rotation entry has epoch {got}, expected dense epoch {expected}")]
    NonDenseEpoch {
        /// The epoch the entry carries.
        got: u64,
        /// The epoch required at this position.
        expected: u64,
    },
    /// An entry's activation does not come after the previous entry's.
    #[error("rotation activation {got} is not after the previous activation {prev}")]
    NonMonotonicActivation {
        /// The previous entry's activation block.
        prev: u64,
        /// The offending entry's activation block.
        got: u64,
    },
    /// An entry activates at or before its own announcement.
    #[error("epoch {epoch} activates at block {activation_block}, which is not after its announcement at block {announced_at_block}")]
    ActivationNotAfterAnnouncement {
        /// The offending epoch.
        epoch: u64,
        /// Its activation block.
        activation_block: u64,
        /// Its announcement block.
        announced_at_block: u64,
    },
    /// A newer schedule disagrees with an already-known entry. The registry is
    /// append-only, so this can only mean a bug or a registry deeper-than-`K` reorg —
    /// both must be surfaced, never silently adopted.
    #[error("rotation history diverged at entry {index}")]
    DivergentHistory {
        /// Index of the first disagreeing entry.
        index: usize,
    },
    /// A newer schedule is shorter than the already-known one.
    #[error("rotation history regressed from {have} entries to {got}")]
    Regression {
        /// Entries already known.
        have: usize,
        /// Entries in the purportedly newer schedule.
        got: usize,
    },
}

/// The append-only rotation history: entry `i` is epoch `i + 1`, activations strictly
/// increase, and every entry activates after its announcement. Carries no key
/// material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationSchedule(Vec<RotationEntry>);

impl RotationSchedule {
    /// An empty schedule: every block is epoch 0.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Builds a schedule from entries, validating every invariant.
    pub fn from_entries(
        entries: impl IntoIterator<Item = RotationEntry>,
    ) -> Result<Self, ScheduleError> {
        let mut schedule = Self::new();
        for entry in entries {
            schedule.push(entry)?;
        }
        Ok(schedule)
    }

    /// Appends the next rotation, enforcing the schedule invariants.
    pub fn push(&mut self, entry: RotationEntry) -> Result<(), ScheduleError> {
        let expected = (self.0.len() as u64).saturating_add(1);
        if entry.epoch != expected {
            return Err(ScheduleError::NonDenseEpoch { got: entry.epoch, expected });
        }
        if entry.activation_block <= entry.announced_at_block {
            return Err(ScheduleError::ActivationNotAfterAnnouncement {
                epoch: entry.epoch,
                activation_block: entry.activation_block,
                announced_at_block: entry.announced_at_block,
            });
        }
        if let Some(last) = self.0.last() {
            if entry.activation_block <= last.activation_block {
                return Err(ScheduleError::NonMonotonicActivation {
                    prev: last.activation_block,
                    got: entry.activation_block,
                });
            }
        }
        self.0.push(entry);
        Ok(())
    }

    /// Extends this schedule to match `newer`, which must be a strict extension of it
    /// (identical prefix). Returns the number of entries appended.
    pub fn extend_to(&mut self, newer: &Self) -> Result<usize, ScheduleError> {
        if newer.0.len() < self.0.len() {
            return Err(ScheduleError::Regression { have: self.0.len(), got: newer.0.len() });
        }
        for (index, (known, incoming)) in self.0.iter().zip(newer.0.iter()).enumerate() {
            if known != incoming {
                return Err(ScheduleError::DivergentHistory { index });
            }
        }
        let mut appended = 0;
        for entry in newer.0.iter().skip(self.0.len()) {
            self.push(*entry)?;
            appended += 1;
        }
        Ok(appended)
    }

    /// The epoch active for `block`: the greatest announced epoch whose activation is
    /// at or before `block`, or 0 if none (the normative function from the design
    /// spec §3.4).
    pub fn epoch_at_block(&self, block: u64) -> u64 {
        self.0
            .iter()
            .rev()
            .find(|entry| entry.activation_block <= block)
            .map(|entry| entry.epoch)
            .unwrap_or(0)
    }

    /// The soonest rotation that has not yet activated as of `tip`, if any.
    pub fn pending_after(&self, tip: u64) -> Option<&RotationEntry> {
        self.0.iter().find(|entry| entry.activation_block > tip)
    }

    /// Number of announced rotations (the registry array length).
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no rotation has ever been announced.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// All announced rotations, in epoch order.
    pub fn entries(&self) -> &[RotationEntry] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // test code

    use super::*;

    fn entry(epoch: u64, activation: u64, announced: u64) -> RotationEntry {
        RotationEntry { epoch, activation_block: activation, announced_at_block: announced }
    }

    #[test]
    fn empty_schedule_is_epoch_zero_everywhere() {
        let schedule = RotationSchedule::new();
        assert_eq!(schedule.epoch_at_block(0), 0);
        assert_eq!(schedule.epoch_at_block(u64::MAX), 0);
        assert!(schedule.pending_after(0).is_none());
    }

    #[test]
    fn epoch_flips_exactly_at_activation() {
        let schedule = RotationSchedule::from_entries([entry(1, 100, 10)]).unwrap();
        assert_eq!(schedule.epoch_at_block(99), 0);
        assert_eq!(schedule.epoch_at_block(100), 1);
        assert_eq!(schedule.epoch_at_block(101), 1);
    }

    #[test]
    fn multi_rotation_selects_greatest_activated() {
        let schedule =
            RotationSchedule::from_entries([entry(1, 100, 10), entry(2, 300, 200)]).unwrap();
        assert_eq!(schedule.epoch_at_block(0), 0);
        assert_eq!(schedule.epoch_at_block(100), 1);
        assert_eq!(schedule.epoch_at_block(299), 1);
        assert_eq!(schedule.epoch_at_block(300), 2);
    }

    #[test]
    fn pending_after_returns_soonest_unactivated() {
        let schedule =
            RotationSchedule::from_entries([entry(1, 100, 10), entry(2, 300, 200)]).unwrap();
        assert_eq!(schedule.pending_after(50), Some(&entry(1, 100, 10)));
        assert_eq!(schedule.pending_after(100), Some(&entry(2, 300, 200)));
        assert_eq!(schedule.pending_after(300), None);
    }

    #[test]
    fn rejects_non_dense_epochs() {
        let mut schedule = RotationSchedule::new();
        assert_eq!(
            schedule.push(entry(2, 100, 10)),
            Err(ScheduleError::NonDenseEpoch { got: 2, expected: 1 })
        );
    }

    #[test]
    fn rejects_non_monotonic_activation() {
        let mut schedule = RotationSchedule::from_entries([entry(1, 100, 10)]).unwrap();
        assert_eq!(
            schedule.push(entry(2, 100, 50)),
            Err(ScheduleError::NonMonotonicActivation { prev: 100, got: 100 })
        );
    }

    #[test]
    fn rejects_activation_not_after_announcement() {
        let mut schedule = RotationSchedule::new();
        assert_eq!(
            schedule.push(entry(1, 10, 10)),
            Err(ScheduleError::ActivationNotAfterAnnouncement {
                epoch: 1,
                activation_block: 10,
                announced_at_block: 10
            })
        );
    }

    #[test]
    fn extend_to_appends_only_the_tail() {
        let mut known = RotationSchedule::from_entries([entry(1, 100, 10)]).unwrap();
        let newer =
            RotationSchedule::from_entries([entry(1, 100, 10), entry(2, 300, 200)]).unwrap();
        assert_eq!(known.extend_to(&newer), Ok(1));
        assert_eq!(known, newer);
        // Idempotent.
        assert_eq!(known.extend_to(&newer), Ok(0));
    }

    #[test]
    fn extend_to_rejects_divergence_and_regression() {
        let mut known = RotationSchedule::from_entries([entry(1, 100, 10)]).unwrap();
        let diverged = RotationSchedule::from_entries([entry(1, 101, 10)]).unwrap();
        assert_eq!(known.extend_to(&diverged), Err(ScheduleError::DivergentHistory { index: 0 }));
        let shorter = RotationSchedule::new();
        assert_eq!(known.extend_to(&shorter), Err(ScheduleError::Regression { have: 1, got: 0 }));
    }

    /// The state-height-independence property from the spec (§3.4): extending the
    /// schedule with later announcements never changes the epoch of an old block.
    #[test]
    fn later_announcements_never_change_old_blocks() {
        let mut schedule = RotationSchedule::from_entries([entry(1, 100, 10)]).unwrap();
        let epochs_before: Vec<u64> = (0..150).map(|b| schedule.epoch_at_block(b)).collect();
        let newer =
            RotationSchedule::from_entries([entry(1, 100, 10), entry(2, 300, 200)]).unwrap();
        schedule.extend_to(&newer).unwrap();
        let epochs_after: Vec<u64> = (0..150).map(|b| schedule.epoch_at_block(b)).collect();
        assert_eq!(epochs_before, epochs_after);
    }
}
