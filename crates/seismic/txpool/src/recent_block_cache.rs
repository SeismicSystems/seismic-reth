//! Bounded cache of recent block hashes for O(1) lookup during transaction validation.

use alloy_primitives::B256;
use std::collections::{HashSet, VecDeque};
use tracing::warn;

/// Maximum number of blocks to look back for `recent_block_hash` validation.
pub const SEISMIC_TX_RECENT_BLOCK_LOOKBACK: u64 = 100;

/// A bounded cache that stores recent block hashes with FIFO eviction.
///
/// Used by [`SeismicTransactionValidator`](crate::SeismicTransactionValidator) to validate
/// `recent_block_hash` in seismic transactions without iterating over blocks via the client.
/// Updated on each new head block via `on_new_head_block`.
#[derive(Debug)]
pub struct RecentBlockCache {
    /// Set of block hashes for O(1) lookup.
    hashes: HashSet<B256>,
    /// Ordered queue of block hashes (front = oldest, back = newest) for FIFO eviction.
    ordered: VecDeque<B256>,
    /// The block number of the most recently inserted block.
    current_block_number: u64,
    /// Maximum number of block hashes to retain.
    max_size: u64,
    /// Tip at/after which the window is whole again. A failed `canonical_hash_at` lookup leaves a
    /// hole; this is set to `missing_block + max_size` (when that block ages out of the window).
    /// `u64::MAX` until the first successful build. See [`is_complete`](Self::is_complete).
    incomplete_until: u64,
}

impl Default for RecentBlockCache {
    fn default() -> Self {
        Self::new(SEISMIC_TX_RECENT_BLOCK_LOOKBACK)
    }
}

impl RecentBlockCache {
    /// Creates a new empty cache with the given maximum size.
    pub fn new(max_size: u64) -> Self {
        Self {
            hashes: HashSet::with_capacity(max_size as usize),
            ordered: VecDeque::with_capacity(max_size as usize),
            current_block_number: 0,
            max_size,
            incomplete_until: u64::MAX,
        }
    }

    /// Whether the lookback window is fully populated (no unfilled hole still in range). Gate
    /// `contains`-based eviction on this so a transient lookup hole isn't read as staleness; it
    /// self-heals once the hole ages out.
    pub const fn is_complete(&self) -> bool {
        self.current_block_number >= self.incomplete_until
    }

    /// Inserts a block hash into the cache, evicting the oldest entry if at capacity.
    pub fn insert(&mut self, hash: B256, block_number: u64) {
        self.current_block_number = block_number;
        self.ordered.push_back(hash);
        self.hashes.insert(hash);
        while self.ordered.len() as u64 > self.max_size {
            if let Some(old) = self.ordered.pop_front() {
                self.hashes.remove(&old);
            }
        }
    }

    /// Returns `true` if the cache contains the given block hash.
    pub fn contains(&self, hash: &B256) -> bool {
        self.hashes.contains(hash)
    }

    /// Returns the block number of the most recently inserted block.
    pub const fn current_block_number(&self) -> u64 {
        self.current_block_number
    }

    /// Returns `true` if the cache is empty (no blocks have been inserted yet).
    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    /// Returns the hash of the most recently inserted block, if any.
    pub fn latest_hash(&self) -> Option<&B256> {
        self.ordered.back()
    }

    /// Clears the cache and repopulates it from the given entries.
    ///
    /// Called on reorgs or any non-sequential block update, since stale hashes from
    /// the old fork must be purged and replaced with the current canonical chain.
    pub fn rebuild(&mut self, entries: impl Iterator<Item = (B256, u64)>) {
        self.hashes.clear();
        self.ordered.clear();
        self.current_block_number = 0;
        for (hash, number) in entries {
            self.insert(hash, number);
        }
        // Caller supplies the entries it considers canonical; treat the window as fully populated.
        self.incomplete_until = 0;
    }

    /// Rebuilds the cache from the canonical chain up to the given tip block number.
    ///
    /// `canonical_hash_at` is a closure that returns the canonical block hash for a
    /// given block number, or `None` if unavailable. This is used both at startup
    /// (to populate the cache) and during reorg recovery.
    pub fn rebuild_to_tip(&mut self, tip: u64, canonical_hash_at: impl Fn(u64) -> Option<B256>) {
        self.rebuild_window(tip, None, "rebuild", canonical_hash_at);
    }

    /// Clears and rebuilds the window `[tip - max_size, tip]` from `canonical_hash_at`.
    ///
    /// `tip_hash`, when supplied, is used for `tip` instead of re-fetching it through the
    /// callback — the caller already has the sealed-block hash, and the client may not yet return
    /// it by number. A missing canonical hash is warned and leaves the window marked incomplete
    /// (see [`is_complete`](Self::is_complete)) rather than being silently skipped.
    fn rebuild_window(
        &mut self,
        tip: u64,
        tip_hash: Option<B256>,
        mode: &str,
        canonical_hash_at: impl Fn(u64) -> Option<B256>,
    ) {
        self.hashes.clear();
        self.ordered.clear();
        self.current_block_number = 0;
        let earliest = tip.saturating_sub(self.max_size);
        let mut newest_hole: Option<u64> = None;
        for n in earliest..=tip {
            let hash = if n == tip {
                tip_hash.or_else(|| canonical_hash_at(n))
            } else {
                canonical_hash_at(n)
            };
            match hash {
                Some(hash) => self.insert(hash, n),
                None => {
                    warn!(target: "seismic::txpool", missing_block = n, tip, mode, "recent block cache: missing canonical hash");
                    // Ascending loop, so this keeps the newest missing block number.
                    newest_hole = Some(n);
                }
            }
        }
        // Whole again once the newest hole ages out of the window (tip = hole + max_size).
        self.incomplete_until = newest_hole.map_or(0, |m| m.saturating_add(self.max_size));
    }

    /// Updates the cache with a new head block, handling gaps and reorgs.
    ///
    /// The cache must always reflect the canonical chain so that validation
    /// accepts exactly the hashes that the RPC layer would return for
    /// `eth_getBlockByNumber("latest")`. Three cases:
    ///
    /// 1. **Sequential block** (`new == cached + 1`): The common case during normal operation. We
    ///    just append the new hash — O(1).
    ///
    /// 2. **Gap but still canonical** (`new > cached` and our latest hash is still on the canonical
    ///    chain): Multiple blocks were produced between callbacks (e.g. between `new()` and the
    ///    first callback, or a slow consumer). We backfill only the missing blocks.
    ///
    /// 3. **Stale cache** (reorg, empty, or same/lower height): The cache contains hashes from a
    ///    fork that is no longer canonical. We clear and rebuild the full lookback window to purge
    ///    stale fork hashes.
    pub fn update(
        &mut self,
        new_hash: B256,
        new_number: u64,
        canonical_hash_at: impl Fn(u64) -> Option<B256>,
    ) {
        // Happy path: sequential block, just append
        if new_number == self.current_block_number + 1 {
            self.insert(new_hash, new_number);
            return;
        }

        // Non-sequential: check if the cache is still on the canonical chain
        if new_number > self.current_block_number && self.is_on_canonical_chain(&canonical_hash_at)
        {
            // Cache is canonical but behind — backfill the gap. Use the supplied `new_hash` for
            // the tip instead of re-fetching it (the client may not return it by number yet).
            let backfill_start = self.current_block_number + 1;
            for n in backfill_start..=new_number {
                let hash = if n == new_number { Some(new_hash) } else { canonical_hash_at(n) };
                match hash {
                    Some(hash) => self.insert(hash, n),
                    None => {
                        warn!(target: "seismic::txpool", missing_block = n, tip = new_number, mode = "backfill", "recent block cache: missing canonical hash");
                        self.incomplete_until =
                            self.incomplete_until.max(n.saturating_add(self.max_size));
                    }
                }
            }
            return;
        }

        // Cache is stale (reorg, empty, or same/lower height) — full rebuild, reusing `new_hash`.
        self.rebuild_window(new_number, Some(new_hash), "rebuild", canonical_hash_at);
    }

    /// Checks whether the cache's latest block is still on the canonical chain.
    ///
    /// Compares the cache's latest hash against what the canonical chain reports for
    /// that block number. Returns `false` if the cache is empty, the block has been
    /// reorged out, or the lookup fails.
    fn is_on_canonical_chain(&self, canonical_hash_at: &impl Fn(u64) -> Option<B256>) -> bool {
        let Some(&cached_hash) = self.latest_hash() else {
            return false;
        };
        canonical_hash_at(self.current_block_number).is_some_and(|h| h == cached_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_contains() {
        let mut cache = RecentBlockCache::new(3);
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);

        cache.insert(h1, 1);
        cache.insert(h2, 2);

        assert!(cache.contains(&h1));
        assert!(cache.contains(&h2));
        assert!(!cache.contains(&B256::from([3u8; 32])));
        assert_eq!(cache.current_block_number(), 2);
    }

    #[test]
    fn test_eviction() {
        let mut cache = RecentBlockCache::new(2);
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        let h3 = B256::from([3u8; 32]);

        cache.insert(h1, 1);
        cache.insert(h2, 2);
        cache.insert(h3, 3);

        // h1 should be evicted
        assert!(!cache.contains(&h1));
        assert!(cache.contains(&h2));
        assert!(cache.contains(&h3));
        assert_eq!(cache.current_block_number(), 3);
    }

    #[test]
    fn test_is_empty() {
        let mut cache = RecentBlockCache::new(5);
        assert!(cache.is_empty());

        cache.insert(B256::from([1u8; 32]), 1);
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_rebuild_replaces_all_entries() {
        let mut cache = RecentBlockCache::new(5);
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);
        let h3 = B256::from([3u8; 32]);
        let h4 = B256::from([4u8; 32]);

        cache.insert(h1, 10);
        cache.insert(h2, 11);

        // Rebuild with completely different entries (simulates a reorg)
        cache.rebuild(vec![(h3, 10), (h4, 11)].into_iter());

        assert!(!cache.contains(&h1));
        assert!(!cache.contains(&h2));
        assert!(cache.contains(&h3));
        assert!(cache.contains(&h4));
        assert_eq!(cache.current_block_number(), 11);
    }

    /// Helper: creates a closure that maps block number -> hash for a slice of (hash, number).
    fn mock_canonical(blocks: &[(B256, u64)]) -> impl Fn(u64) -> Option<B256> + '_ {
        move |n| blocks.iter().find(|(_, num)| *num == n).map(|(h, _)| *h)
    }

    #[test]
    fn test_rebuild_to_tip() {
        let mut cache = RecentBlockCache::new(3);
        let h8 = B256::from([8u8; 32]);
        let h9 = B256::from([9u8; 32]);
        let h10 = B256::from([10u8; 32]);

        let blocks = [(h8, 8), (h9, 9), (h10, 10)];
        cache.rebuild_to_tip(10, mock_canonical(&blocks));

        assert!(cache.contains(&h8));
        assert!(cache.contains(&h9));
        assert!(cache.contains(&h10));
        assert_eq!(cache.current_block_number(), 10);
    }

    #[test]
    fn test_update_sequential() {
        let mut cache = RecentBlockCache::new(5);
        let h1 = B256::from([1u8; 32]);
        let h2 = B256::from([2u8; 32]);

        cache.insert(h1, 1);
        // Sequential: block 2 follows block 1
        #[allow(clippy::panic)]
        cache.update(h2, 2, |_| panic!("should not be called for sequential"));

        assert!(cache.contains(&h1));
        assert!(cache.contains(&h2));
        assert_eq!(cache.current_block_number(), 2);
    }

    #[test]
    fn test_update_gap_still_canonical() {
        let mut cache = RecentBlockCache::new(10);
        let h5 = B256::from([5u8; 32]);
        let h6 = B256::from([6u8; 32]);
        let h7 = B256::from([7u8; 32]);
        let h8 = B256::from([8u8; 32]);

        cache.insert(h5, 5);

        // Gap: jump from 5 to 8, but cache is still canonical
        let blocks = [(h5, 5), (h6, 6), (h7, 7), (h8, 8)];
        cache.update(h8, 8, mock_canonical(&blocks));

        assert!(cache.contains(&h5));
        assert!(cache.contains(&h6));
        assert!(cache.contains(&h7));
        assert!(cache.contains(&h8));
        assert_eq!(cache.current_block_number(), 8);
    }

    #[test]
    fn test_backfill_uses_supplied_hash_for_tip() {
        let mut cache = RecentBlockCache::new(100);
        let h5 = B256::from([5u8; 32]);
        cache.insert(h5, 5);

        // Backfill 6..=8 where the callback knows 5 (canonical check), 6, 7 but not the tip 8.
        let h6 = B256::from([6u8; 32]);
        let h7 = B256::from([7u8; 32]);
        let tip = B256::from([88u8; 32]);
        cache.update(tip, 8, mock_canonical(&[(h5, 5), (h6, 6), (h7, 7)]));

        // The tip is taken from `new_hash`, not the (missing) callback result.
        assert!(cache.contains(&tip));
        assert_eq!(cache.current_block_number(), 8);
    }

    #[test]
    fn test_rebuild_uses_supplied_hash_for_tip() {
        let mut cache = RecentBlockCache::new(100);
        cache.insert(B256::from([5u8; 32]), 5);

        // Same-height, different hash -> stale -> full rebuild. The callback returns nothing, but
        // the tip must still be taken from `new_hash`.
        let tip = B256::from([66u8; 32]);
        cache.update(tip, 5, |_| None);

        assert!(cache.contains(&tip));
        assert_eq!(cache.current_block_number(), 5);
    }

    #[test]
    fn test_update_reorg_triggers_rebuild() {
        let mut cache = RecentBlockCache::new(5);
        let h5_old = B256::from([50u8; 32]);
        let h6_old = B256::from([60u8; 32]);
        let h7_old = B256::from([70u8; 32]);
        let h5_new = B256::from([55u8; 32]);
        let h6_new = B256::from([66u8; 32]);

        cache.insert(h5_old, 5);
        cache.insert(h6_old, 6);
        cache.insert(h7_old, 7);

        // Reorg: new canonical chain is shorter (tip at 6), old fork hashes are stale.
        // new_number (6) <= current_block_number (7), so this triggers a full rebuild.
        let blocks = [(h5_new, 5), (h6_new, 6)];
        cache.update(h6_new, 6, mock_canonical(&blocks));

        // Old fork hashes should be gone, new canonical hashes present
        assert!(!cache.contains(&h5_old));
        assert!(!cache.contains(&h6_old));
        assert!(!cache.contains(&h7_old));
        assert!(cache.contains(&h5_new));
        assert!(cache.contains(&h6_new));
        assert_eq!(cache.current_block_number(), 6);
    }

    #[test]
    fn test_update_same_height_triggers_rebuild() {
        let mut cache = RecentBlockCache::new(5);
        let h5_old = B256::from([50u8; 32]);
        let h5_new = B256::from([55u8; 32]);

        cache.insert(h5_old, 5);

        // Same height but different hash (reorg at same level)
        let blocks = [(h5_new, 5)];
        cache.update(h5_new, 5, mock_canonical(&blocks));

        assert!(!cache.contains(&h5_old));
        assert!(cache.contains(&h5_new));
        assert_eq!(cache.current_block_number(), 5);
    }

    #[test]
    fn test_is_complete_tracks_window_holes() {
        let h = |i: u8| B256::from([i; 32]);

        // Fresh cache: nothing built yet.
        let mut cache = RecentBlockCache::new(5);
        assert!(!cache.is_complete());

        // Full rebuild over the whole window (blocks 0..=3 all present) -> complete.
        let full = [(h(0), 0), (h(1), 1), (h(2), 2), (h(3), 3)];
        cache.rebuild_to_tip(3, mock_canonical(&full));
        assert!(cache.is_complete());

        // Rebuild with block 2 missing -> a hole -> incomplete (whole again at block 2 + 5 = 7).
        let holey = [(h(0), 0), (h(1), 1), (h(3), 3)];
        cache.rebuild_to_tip(3, mock_canonical(&holey));
        assert!(!cache.is_complete());

        // Sequential appends must not paper over the hole while it is still in the window...
        cache.update(h(4), 4, |_| None);
        assert!(!cache.is_complete());
        cache.update(h(5), 5, |_| None);
        cache.update(h(6), 6, |_| None);
        assert!(!cache.is_complete());

        // ...but once block 2 ages out of the window (tip reaches 7), it self-heals — no rebuild.
        cache.update(h(7), 7, |_| None);
        assert!(cache.is_complete());

        // A clean full rebuild also restores completeness directly.
        let holey = [(h(3), 3), (h(5), 5), (h(6), 6), (h(7), 7)];
        cache.rebuild_to_tip(7, mock_canonical(&holey));
        assert!(!cache.is_complete()); // block 4 missing -> incomplete
        let full = [(h(3), 3), (h(4), 4), (h(5), 5), (h(6), 6), (h(7), 7)];
        cache.rebuild_to_tip(7, mock_canonical(&full));
        assert!(cache.is_complete());
    }
}
