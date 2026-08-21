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
        cache.update(tip.hash(), tip.number(), tip.parent_hash(), |n| {
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
