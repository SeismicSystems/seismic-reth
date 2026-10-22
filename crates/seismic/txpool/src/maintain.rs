//! Registry-backed pool maintenance and stale Seismic transaction eviction.

use crate::{
    payment::ProviderRegistryStorage, recent_block_cache::RecentBlockCache,
    transaction::SeismicPooledTransaction, validator::seismic_freshness_error, SeismicBalanceError,
};
use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, Sealable, TxHash};
use futures_util::StreamExt;
use reth_execution_types::ChangedAccount;
use reth_provider::{BlockReaderIdExt, CanonStateNotificationStream, StateProvider};
use reth_seismic_primitives::SeismicPrimitives;
use reth_transaction_pool::{
    maintain::{CanonicalStorageChanges, ChangedAccountsHook},
    PoolTransaction, TransactionPool, ValidPoolTransaction,
};
use seismic_alloy_consensus::SeismicTypedTransaction;
use seismic_revm::gas_token_registry::{
    aggregate_balance, balance_storage_key, visit_registered_tokens, GAS_TOKEN_REGISTRY,
};
use std::{collections::HashSet, sync::Arc};
use tracing::debug;

#[cfg(test)]
mod tests;

/// Registry-backed aggregate balance and targeted token-holder discovery.
///
/// Uses the same shared aggregate as admission, without selecting a transaction's
/// payment asset. Actual registry changes refresh every pooled sender; token-only
/// changes match full-width balance mapping keys for known pooled senders. Both
/// removed and added reorg branches are inspected, but balances are read at the new tip.
///
/// Reads use the maintenance snapshot. All aggregates succeed before any record is
/// mutated. Failed batches remain dirty instead of reporting zero token funds, and
/// read-only discovery does not fetch holder balances.
#[derive(Debug, Default)]
pub struct SeismicBalanceHook;

impl ChangedAccountsHook for SeismicBalanceHook {
    type Error = SeismicBalanceError;

    fn affected_accounts(
        &self,
        state: &dyn StateProvider,
        changes: &dyn CanonicalStorageChanges,
        pooled_senders: &HashSet<Address>,
    ) -> Result<HashSet<Address>, Self::Error> {
        if pooled_senders.is_empty() || !changes.has_storage_changes() {
            return Ok(HashSet::new())
        }
        if changes.storage_changed(GAS_TOKEN_REGISTRY) {
            return Ok(pooled_senders.clone())
        }

        let mut affected = HashSet::new();
        let mut reader = ProviderRegistryStorage(state);
        visit_registered_tokens(&mut reader, |token| {
            if changes.storage_changed(token.token) {
                for &sender in pooled_senders {
                    if changes
                        .slot_changed(token.token, balance_storage_key(sender, token.balance_slot))
                    {
                        affected.insert(sender);
                    }
                }
            }
        })?;
        Ok(affected)
    }

    fn transform(
        &self,
        state: &dyn StateProvider,
        accounts: &mut [ChangedAccount],
    ) -> Result<(), Self::Error> {
        // Stage all reads before mutating the batch so a later read failure cannot
        // leave partially augmented records, including for callers outside maintenance.
        let balances = accounts
            .iter()
            .map(|acc| {
                aggregate_balance(&mut ProviderRegistryStorage(state), acc.address, acc.balance)
                    .map_err(SeismicBalanceError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (acc, balance) in accounts.iter_mut().zip(balances) {
            if balance != acc.balance {
                debug!(target: "seismic::txpool", "augmenting changed account balance with registry tokens");
                acc.balance = balance;
            }
        }
        Ok(())
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
