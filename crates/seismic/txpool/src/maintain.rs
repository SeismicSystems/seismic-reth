//! Seismic-specific pool maintenance: a [`ChangedAccountsHook`] that augments native balances with
//! USDC predeploy balances, and a background task that evicts stale Seismic transactions.

use crate::{
    recent_block_cache::RecentBlockCache, transaction::SeismicPooledTransaction,
    validator::seismic_freshness_error,
};
use alloy_consensus::BlockHeader;
use alloy_primitives::{Sealable, TxHash};
use futures_util::StreamExt;
use reth_execution_types::ChangedAccount;
use reth_provider::{BlockReaderIdExt, CanonStateNotificationStream, StateProvider};
use reth_seismic_primitives::SeismicPrimitives;
use reth_transaction_pool::{
    maintain::ChangedAccountsHook, PoolTransaction, TransactionPool, ValidPoolTransaction,
};
use seismic_alloy_consensus::SeismicTypedTransaction;
use std::sync::Arc;
use tracing::debug;

/// Makes the transaction pool's balance accounting aware of USDC gas payment.
///
/// On Seismic, gas can be paid in USDC, but the pool tracks a single native
/// balance per account and uses it to promote/demote transactions between the
/// Pending and Queued subpools. Without help, an account paying gas in USDC
/// (with little or no native balance) looks broke to the pool, so its otherwise
/// valid transactions end up parked in the Queued subpool — never promoted to
/// Pending, or demoted back out of it — and are never mined. This
/// [`ChangedAccountsHook`] augments that per-account balance with the sender's
/// USDC balance so those decisions are accurate. It runs in the maintenance loop
/// on new blocks/reorgs and only feeds promote/demote — admission is gated
/// separately by the validator (see [`crate::usdc::can_afford`]).
///
/// The pool's single scalar can't express the validator's component-wise rule
/// (value from native, gas from remaining native or USDC). We report
/// `native + usdc` instead, a sound upper bound: any transaction the validator
/// admits satisfies `cost ≤ native + usdc`, so the pool's `cost ≤ balance` check
/// never parks it in Queued. Keep in sync with the scalar reported by the
/// validator (see `validator.rs`).
///
/// The sum over-promotes only when an account overcommits its *native* balance
/// across multiple value-bearing txs (value=0 gas traffic is gated near-exactly).
/// Such a tx then fails at block building, the final affordability gate. That is
/// safe: an unincluded tx consumes no nonce — it just lingers in the pending
/// subpool and blocks higher nonces from the same sender until balances change
/// (standard stuck-nonce behavior, not on-chain inconsistency).
///
/// Implementation: for each changed account it sets `balance = native + usdc_scaled`
/// ([`crate::usdc::read_usdc_balance`]), reading USDC via the [`StateProvider`] the
/// maintenance loop passes in rather than its own snapshot, so USDC is read from the
/// same block as the native balance and nonce.
#[derive(Debug, Default)]
pub struct SeismicBalanceHook;

impl ChangedAccountsHook for SeismicBalanceHook {
    fn transform(&self, state: &dyn StateProvider, accounts: &mut Vec<ChangedAccount>) {
        for acc in accounts.iter_mut() {
            let usdc = crate::usdc::read_usdc_balance(state, &acc.address);
            let new_balance = acc.balance.saturating_add(usdc);
            if new_balance != acc.balance {
                debug!(
                    target: "seismic::txpool",
                    address = %acc.address,
                    native_balance = %acc.balance,
                    usdc_scaled_balance = %usdc,
                    pool_balance = %new_balance,
                    "augmenting changed account balance with USDC"
                );
                acc.balance = new_balance;
            }
        }
    }
}

/// Run the full-pool scan every Nth head (the cache still updates every head). Eviction is just
/// cleanup — the builder skips stale txs regardless — so a little latency is fine.
const SCAN_EVERY_N_BLOCKS: u64 = 4;

/// Background task that evicts pooled Seismic txs whose freshness window has lapsed.
///
/// A tx fresh at ingress can go stale while parked behind a nonce gap (ingress doesn't re-run),
/// then get re-selected by the builder every block. The cache refreshes each head; the eviction
/// scan runs every [`SCAN_EVERY_N_BLOCKS`].
pub async fn maintain_seismic_freshness<Client, Pool>(
    client: Client,
    pool: Pool,
    mut events: CanonStateNotificationStream<SeismicPrimitives>,
) where
    Client: BlockReaderIdExt + 'static,
    Pool: TransactionPool<Transaction = SeismicPooledTransaction>,
{
    // Seed the cache from the canonical chain so the first notification has a full lookback window.
    let mut cache = RecentBlockCache::default();
    if let Ok(tip) = client.best_block_number() {
        cache.rebuild_to_tip(tip, |n| client.header_by_number(n).ok()?.map(|h| h.hash_slow()));
    }

    let mut heads_since_scan = 0u64;
    while let Some(notification) = events.next().await {
        let Some(tip) = notification.tip_checked() else { continue };
        cache.update(tip.hash(), tip.number(), |n| {
            client.header_by_number(n).ok()?.map(|h| h.hash_slow())
        });

        heads_since_scan += 1;
        if heads_since_scan < SCAN_EVERY_N_BLOCKS {
            continue;
        }
        heads_since_scan = 0;

        let all = pool.all_transactions();
        let stale = stale_seismic_hashes(all.pending.iter().chain(all.queued.iter()), &cache);
        if !stale.is_empty() {
            let removed = pool.remove_transactions(stale);
            debug!(
                target: "seismic::txpool",
                count = removed.len(),
                current_block = cache.current_block_number(),
                "evicted stale seismic transactions"
            );
        }
    }
}

/// Hashes of pooled Seismic txs whose freshness window has lapsed. Pure, so testable and benchable.
/// `recent_block_hash` is gated on [`RecentBlockCache::is_complete`]; expiry always applies.
pub fn stale_seismic_hashes<'a>(
    txs: impl IntoIterator<Item = &'a Arc<ValidPoolTransaction<SeismicPooledTransaction>>>,
    cache: &RecentBlockCache,
) -> Vec<TxHash> {
    let check_recent_hash = cache.is_complete();
    txs.into_iter()
        .filter_map(|tx| {
            let consensus_tx = tx.transaction.clone_into_consensus();
            let SeismicTypedTransaction::Seismic(seismic_tx) = consensus_tx.transaction() else {
                return None;
            };
            seismic_freshness_error(&seismic_tx.seismic_elements, cache, check_recent_hash)
                .map(|_| *tx.hash())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::transaction::Recovered;
    use alloy_eips::Encodable2718;
    use alloy_primitives::{Address, FlaggedStorage, B256, U256};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_seismic_primitives::test_utils::get_signed_seismic_tx;
    use reth_transaction_pool::identifier::{SenderId, TransactionId};
    use std::time::Instant;

    /// Builds a pooled Seismic tx referencing `recent_block_hash`. Mirrors
    /// `txpool/benches/eviction_scan.rs::make_tx`; the default
    /// `expires_at_block` baked into [`get_signed_seismic_tx`] is `1_000_000`
    /// (see `reth_seismic_primitives::test_utils::get_seismic_elements`).
    fn make_tx(recent_block_hash: B256) -> Arc<ValidPoolTransaction<SeismicPooledTransaction>> {
        let recovered =
            Recovered::new_unchecked(get_signed_seismic_tx(recent_block_hash), Address::ZERO);
        let len = recovered.encode_2718_len();
        Arc::new(ValidPoolTransaction {
            transaction: SeismicPooledTransaction::new(recovered, len),
            transaction_id: TransactionId::new(SenderId::from(1u64), 1),
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    // ---- stale_seismic_hashes ----

    #[test]
    fn stale_seismic_hashes_keeps_fresh_tx() {
        let hash = B256::repeat_byte(1);
        let mut cache = RecentBlockCache::new(10);
        // `rebuild` marks the cache complete (`incomplete_until = 0`), tip well within the
        // tx's default 1_000_000 expiry, and the tx's own recent_block_hash is present.
        cache.rebuild(std::iter::once((hash, 100)));
        let tx = make_tx(hash);

        let stale = stale_seismic_hashes(std::iter::once(&tx), &cache);
        assert!(stale.is_empty(), "a tx within its lookback window and not expired must not evict");
    }

    #[test]
    fn stale_seismic_hashes_evicts_expired_tx() {
        let hash = B256::repeat_byte(1);
        let mut cache = RecentBlockCache::new(10);
        // recent_block_hash is present (isolates the expiry check), but the tip is past the
        // tx's default expires_at_block of 1_000_000.
        cache.rebuild(std::iter::once((hash, 1_000_001)));
        let tx = make_tx(hash);

        let stale = stale_seismic_hashes(std::iter::once(&tx), &cache);
        assert_eq!(stale, vec![*tx.hash()], "a tx past its expires_at_block must be evicted");
    }

    #[test]
    fn stale_seismic_hashes_evicts_when_recent_hash_missing_and_cache_complete() {
        let referenced_hash = B256::repeat_byte(1); // what the tx points at
        let cached_hash = B256::repeat_byte(2); // what's actually canonical
        let mut cache = RecentBlockCache::new(10);
        // Complete cache (rebuild -> incomplete_until = 0) that never saw `referenced_hash`,
        // e.g. because it was reorged out. Tip (50) is well within the expiry window, so this
        // isolates the recent_block_hash check from the expiry check.
        cache.rebuild(std::iter::once((cached_hash, 50)));
        let tx = make_tx(referenced_hash);

        let stale = stale_seismic_hashes(std::iter::once(&tx), &cache);
        assert_eq!(
            stale,
            vec![*tx.hash()],
            "a tx whose recent_block_hash isn't canonical must be evicted once the cache is complete"
        );
    }

    #[test]
    fn stale_seismic_hashes_does_not_evict_when_cache_incomplete() {
        // A freshly constructed cache starts incomplete (`incomplete_until = u64::MAX`,
        // `current_block_number = 0`) until the first successful rebuild.
        let cache = RecentBlockCache::new(10);
        assert!(!cache.is_complete());
        let tx = make_tx(B256::repeat_byte(1)); // hash the cache never saw

        let stale = stale_seismic_hashes(std::iter::once(&tx), &cache);
        assert!(
            stale.is_empty(),
            "a transient cache hole must not evict a possibly-valid tx (see is_complete docs)"
        );
    }

    #[test]
    fn stale_seismic_hashes_filters_multiple_txs_independently() {
        let known_hash = B256::repeat_byte(1);
        let unknown_hash = B256::repeat_byte(2);
        let mut cache = RecentBlockCache::new(10);
        cache.rebuild(std::iter::once((known_hash, 50)));

        let fresh_tx = make_tx(known_hash);
        let stale_tx = make_tx(unknown_hash);
        let txs = vec![fresh_tx.clone(), stale_tx.clone()];

        let stale = stale_seismic_hashes(txs.iter(), &cache);
        assert_eq!(
            stale,
            vec![*stale_tx.hash()],
            "only the tx with the missing recent_block_hash should be reported stale"
        );
    }

    // ---- SeismicBalanceHook ----

    #[test]
    fn balance_hook_augments_balance_with_usdc() {
        let addr = Address::with_last_byte(0xab);
        let key = crate::usdc::usdc_balance_storage_key(&addr);
        let raw_usdc = U256::from(5_000_000u64); // 5 USDC at 6 decimals

        let provider = MockEthProvider::default();
        provider.add_account(
            crate::usdc::USDC_CONTRACT,
            ExtendedAccount::new(0, U256::ZERO)
                .extend_storage([(key, FlaggedStorage::new(raw_usdc, false))]),
        );

        let native = U256::from(1_000u64);
        let mut accounts = vec![ChangedAccount { address: addr, nonce: 0, balance: native }];
        SeismicBalanceHook.transform(&provider, &mut accounts);

        let scaled_usdc = raw_usdc * crate::usdc::USDC_DECIMAL_SCALE;
        assert_eq!(accounts[0].balance, native + scaled_usdc);
    }

    #[test]
    fn balance_hook_leaves_balance_unchanged_without_usdc() {
        let addr = Address::with_last_byte(0xcd);
        let provider = MockEthProvider::default(); // no USDC storage for `addr`
        let native = U256::from(777u64);
        let mut accounts = vec![ChangedAccount { address: addr, nonce: 3, balance: native }];

        SeismicBalanceHook.transform(&provider, &mut accounts);

        assert_eq!(accounts[0].balance, native);
        assert_eq!(accounts[0].nonce, 3, "transform must only touch balance");
    }

    #[test]
    fn balance_hook_augments_multiple_accounts_independently() {
        let addr_with_usdc = Address::with_last_byte(0x01);
        let addr_without_usdc = Address::with_last_byte(0x02);
        let key = crate::usdc::usdc_balance_storage_key(&addr_with_usdc);
        let raw_usdc = U256::from(1_000_000u64); // 1 USDC

        let provider = MockEthProvider::default();
        provider.add_account(
            crate::usdc::USDC_CONTRACT,
            ExtendedAccount::new(0, U256::ZERO)
                .extend_storage([(key, FlaggedStorage::new(raw_usdc, false))]),
        );

        let mut accounts = vec![
            ChangedAccount { address: addr_with_usdc, nonce: 0, balance: U256::from(10u64) },
            ChangedAccount { address: addr_without_usdc, nonce: 0, balance: U256::from(20u64) },
        ];
        SeismicBalanceHook.transform(&provider, &mut accounts);

        let scaled_usdc = raw_usdc * crate::usdc::USDC_DECIMAL_SCALE;
        assert_eq!(accounts[0].balance, U256::from(10u64) + scaled_usdc);
        assert_eq!(
            accounts[1].balance,
            U256::from(20u64),
            "account without USDC storage is untouched"
        );
    }
}
