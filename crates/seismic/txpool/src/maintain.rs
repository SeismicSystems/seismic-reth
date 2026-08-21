//! Seismic-specific pool maintenance: a [`ChangedAccountsHook`] that augments native balances with
//! USDC predeploy balances, and a background task that evicts stale Seismic transactions.

use crate::{
    recent_block_cache::RecentBlockCache, transaction::SeismicPooledTransaction,
    validator::seismic_freshness_error,
};
use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, Sealable, TxHash, B256};
use futures_util::StreamExt;
use reth_execution_types::{ChangedAccount, ExecutionOutcome};
use reth_provider::{BlockReaderIdExt, CanonStateNotificationStream, StateProvider};
use reth_seismic_primitives::SeismicPrimitives;
use reth_transaction_pool::{
    maintain::ChangedAccountsHook, PoolTransaction, TransactionPool, ValidPoolTransaction,
};
use seismic_alloy_consensus::SeismicTypedTransaction;
use std::{collections::HashSet, sync::Arc};
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

    fn extend_reload_queued_senders<R>(
        &self,
        queued_senders: &HashSet<Address>,
        old: Option<&ExecutionOutcome<R>>,
        new: &ExecutionOutcome<R>,
        dirty_addresses: &mut HashSet<Address>,
    ) {
        dirty_addresses.extend(queued_senders_with_changed_usdc_slots(queued_senders, old, new));
    }
}

fn queued_senders_with_changed_usdc_slots<'a, R>(
    queued_senders: &'a HashSet<Address>,
    old: Option<&ExecutionOutcome<R>>,
    new: &ExecutionOutcome<R>,
) -> impl Iterator<Item = Address> + 'a {
    let changed_slots = changed_usdc_storage_slots(new)
        .chain(old.into_iter().flat_map(changed_usdc_storage_slots))
        .collect::<HashSet<_>>();

    queued_senders.iter().copied().filter(move |address| {
        changed_slots.contains(&crate::usdc::usdc_balance_storage_key(address))
    })
}

fn changed_usdc_storage_slots<R>(state: &ExecutionOutcome<R>) -> impl Iterator<Item = B256> + '_ {
    state
        .bundle_accounts_iter()
        .filter_map(|(address, account)| (address == crate::usdc::USDC_CONTRACT).then_some(account))
        .flat_map(|account| {
            account
                .storage
                .iter()
                .filter(|(_, value)| value.is_changed())
                .map(|(slot, _)| B256::from(slot.to_be_bytes::<32>()))
        })
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
    use alloy_primitives::{map::HashMap, FlaggedStorage, U256};
    use reth_execution_types::{BundleStateInit, RevertsInit};

    #[test]
    fn reloads_only_queued_senders_with_changed_usdc_slots() {
        let affected = alloy_primitives::address!("000000000000000000000000000000000000000a");
        let unaffected = alloy_primitives::address!("000000000000000000000000000000000000000b");
        let queued_senders = HashSet::from([affected, unaffected]);
        let state = execution_outcome_with_changed_usdc_slots([affected]);

        let dirty = queued_senders_with_changed_usdc_slots(&queued_senders, None, &state)
            .collect::<HashSet<_>>();

        assert_eq!(dirty, HashSet::from([affected]));
    }

    #[test]
    fn includes_changed_slots_from_old_and_new_state() {
        let old_sender = alloy_primitives::address!("000000000000000000000000000000000000000a");
        let new_sender = alloy_primitives::address!("000000000000000000000000000000000000000b");
        let queued_senders = HashSet::from([old_sender, new_sender]);
        let old = execution_outcome_with_changed_usdc_slots([old_sender]);
        let new = execution_outcome_with_changed_usdc_slots([new_sender]);

        let dirty = queued_senders_with_changed_usdc_slots(&queued_senders, Some(&old), &new)
            .collect::<HashSet<_>>();

        assert_eq!(dirty, HashSet::from([old_sender, new_sender]));
    }

    fn execution_outcome_with_changed_usdc_slots(
        senders: impl IntoIterator<Item = Address>,
    ) -> ExecutionOutcome<()> {
        let mut init = BundleStateInit::default();
        init.insert(
            crate::usdc::USDC_CONTRACT,
            (
                None,
                None,
                senders
                    .into_iter()
                    .map(|sender| {
                        (
                            crate::usdc::usdc_balance_storage_key(&sender),
                            (FlaggedStorage::ZERO, FlaggedStorage::from(U256::from(1))),
                        )
                    })
                    .collect::<HashMap<_, _>>(),
            ),
        );

        ExecutionOutcome::new_init(init, RevertsInit::default(), [], vec![], 0, vec![])
    }
}
