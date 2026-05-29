//! Seismic-specific pool maintenance hook that augments native balances with
//! USDC predeploy balances.

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
use reth_transaction_pool::{maintain::ChangedAccountsHook, TransactionPool, ValidPoolTransaction};
use seismic_alloy_consensus::SeismicTypedTransaction;
use std::sync::Arc;
use tracing::debug;

/// A [`ChangedAccountsHook`] that reads each sender's USDC predeploy balance
/// and sets `balance = max(native, usdc_scaled)` so the pool can make accurate
/// demotion decisions for accounts paying gas in USDC.
///
/// The hook uses the [`StateProvider`] passed by the maintenance loop rather
/// than opening its own snapshot, so the USDC balance is always read from the
/// same block as the native balance and nonce.
#[derive(Debug, Default)]
pub struct SeismicBalanceHook;

impl ChangedAccountsHook for SeismicBalanceHook {
    fn transform(&self, state: &dyn StateProvider, accounts: &mut Vec<ChangedAccount>) {
        for acc in accounts.iter_mut() {
            let usdc = crate::usdc::read_usdc_balance(state, &acc.address);
            let new_balance = std::cmp::max(acc.balance, usdc);
            if new_balance != acc.balance {
                debug!(
                    target: "seismic::txpool",
                    address = %acc.address,
                    native_balance = %acc.balance,
                    usdc_scaled_balance = %usdc,
                    effective_balance = %new_balance,
                    "augmenting changed account balance with USDC"
                );
                acc.balance = new_balance;
            }
        }
    }
}

/// Throttle: run the full-pool scan only every Nth head (the cache still updates every head).
/// Eviction is non-urgent cleanup — the builder skips stale txs regardless — so this trades a
/// little eviction latency for less per-block work and pool-lock contention.
const SCAN_EVERY_N_BLOCKS: u64 = 4;

/// Background task that evicts pooled Seismic txs whose freshness window has lapsed.
///
/// A tx can pass the freshness checks at ingress and later go stale while parked behind a nonce
/// gap (ingress validation does not re-run). Without eviction such a tx lingers in the pool and is
/// re-selected by the builder every block. The recent-block cache is refreshed on every head; the
/// scan that removes stale Seismic txs (pending or queued) runs every [`SCAN_EVERY_N_BLOCKS`].
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

/// Hashes of pooled Seismic txs whose freshness window has lapsed. Pure (testable/benchable),
/// reads each tx by reference and skips non-Seismic txs. `recent_block_hash` is gated on
/// [`RecentBlockCache::is_complete`]; expiry always applies.
pub fn stale_seismic_hashes<'a>(
    txs: impl IntoIterator<Item = &'a Arc<ValidPoolTransaction<SeismicPooledTransaction>>>,
    cache: &RecentBlockCache,
) -> Vec<TxHash> {
    let check_recent_hash = cache.is_complete();
    txs.into_iter()
        .filter_map(|tx| {
            let SeismicTypedTransaction::Seismic(seismic_tx) =
                tx.transaction.recovered().transaction()
            else {
                return None;
            };
            seismic_freshness_error(&seismic_tx.seismic_elements, cache, check_recent_hash)
                .map(|_| *tx.hash())
        })
        .collect()
}
