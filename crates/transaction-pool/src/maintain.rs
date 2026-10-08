//! Support for maintaining the state of the transaction pool

use crate::{
    blobstore::{BlobStoreCanonTracker, BlobStoreUpdates},
    error::PoolError,
    metrics::MaintainPoolMetrics,
    traits::{CanonicalStateUpdate, EthPoolTransaction, TransactionPool, TransactionPoolExt},
    BlockInfo, PoolTransaction, PoolUpdateKind, TransactionOrigin,
};
use alloy_consensus::{BlockHeader, Typed2718};
use alloy_eips::{BlockNumberOrTag, Decodable2718, Encodable2718};
use alloy_primitives::{Address, BlockHash, BlockNumber, U256};
use alloy_rlp::{Bytes, Encodable};
use futures_util::{
    future::{BoxFuture, Fuse, FusedFuture},
    FutureExt, Stream, StreamExt,
};
use reth_chain_state::CanonStateNotification;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_execution_types::{ChangedAccount, ExecutionOutcome};
use reth_fs_util::FsPathError;
use reth_primitives_traits::{
    transaction::signed::SignedTransaction, NodePrimitives, SealedHeader,
};
use reth_storage_api::{
    errors::provider::ProviderError, AccountReader, BlockReaderIdExt, StateProvider,
    StateProviderBox, StateProviderFactory,
};
use reth_tasks::TaskSpawner;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::HashSet,
    convert::Infallible,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    sync::oneshot,
    time::{self, Duration},
};
use tracing::{debug, error, info, trace, warn};

/// Maximum amount of time non-executable transaction are queued.
pub const MAX_QUEUED_TRANSACTION_LIFETIME: Duration = Duration::from_secs(3 * 60 * 60);

/// Additional settings for maintaining the transaction pool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintainPoolConfig {
    /// Maximum (reorg) depth we handle when updating the transaction pool: `new.number -
    /// last_seen.number`
    ///
    /// Default: 64 (2 epochs)
    pub max_update_depth: u64,
    /// Maximum number of accounts to reload from state at once when updating the transaction pool.
    ///
    /// Default: 100
    pub max_reload_accounts: usize,

    /// Maximum amount of time non-executable, non local transactions are queued.
    /// Default: 3 hours
    pub max_tx_lifetime: Duration,

    /// Apply no exemptions to the locally received transactions.
    ///
    /// This includes:
    ///   - no price exemptions
    ///   - no eviction exemptions
    pub no_local_exemptions: bool,
}

impl Default for MaintainPoolConfig {
    fn default() -> Self {
        Self {
            max_update_depth: 64,
            max_reload_accounts: 100,
            max_tx_lifetime: MAX_QUEUED_TRANSACTION_LIFETIME,
            no_local_exemptions: false,
        }
    }
}

/// Settings for local transaction backup task
#[derive(Debug, Clone, Default)]
pub struct LocalTransactionBackupConfig {
    /// Path to transactions backup file
    pub transactions_path: Option<PathBuf>,
}

impl LocalTransactionBackupConfig {
    /// Receive path to transactions backup and return initialized config
    pub const fn with_local_txs_backup(transactions_path: PathBuf) -> Self {
        Self { transactions_path: Some(transactions_path) }
    }
}

/// Receipt-independent view of actual canonical storage changes.
///
/// Includes both removed and added branches on reorgs. Comparisons include storage
/// privacy flags; account destruction/deletion counts as changing every storage key.
pub trait CanonicalStorageChanges {
    /// Whether any storage changed, excluding read-only cached slots.
    fn has_storage_changes(&self) -> bool;

    /// Whether an account's storage changed or was wiped.
    fn storage_changed(&self, address: Address) -> bool;

    /// Whether this key changed, including visibility changes or an account-wide wipe.
    fn slot_changed(&self, address: Address, key: U256) -> bool;
}

/// Borrow execution outcomes without copying storage maps or depending on receipt types.
struct CanonicalStorageChangeView<'a, R> {
    new: &'a ExecutionOutcome<R>,
    old: Option<&'a ExecutionOutcome<R>>,
}

impl<R> CanonicalStorageChangeView<'_, R> {
    fn outcomes(&self) -> impl Iterator<Item = &ExecutionOutcome<R>> {
        std::iter::once(self.new).chain(self.old)
    }
}

impl<R> CanonicalStorageChanges for CanonicalStorageChangeView<'_, R> {
    fn has_storage_changes(&self) -> bool {
        self.outcomes().any(|outcome| {
            outcome.state().state.values().any(|account| {
                account.was_destroyed() ||
                    (account.original_info.is_some() && account.info.is_none()) ||
                    account.storage.values().any(|slot| slot.is_changed())
            })
        })
    }

    fn storage_changed(&self, address: Address) -> bool {
        self.outcomes().any(|outcome| {
            outcome.state().state.get(&address).is_some_and(|account| {
                account.was_destroyed() ||
                    (account.original_info.is_some() && account.info.is_none()) ||
                    account.storage.values().any(|slot| slot.is_changed())
            })
        })
    }

    fn slot_changed(&self, address: Address, key: U256) -> bool {
        self.outcomes().any(|outcome| {
            outcome.state().state.get(&address).is_some_and(|account| {
                account.was_destroyed() ||
                    (account.original_info.is_some() && account.info.is_none()) ||
                    account.storage.get(&key).is_some_and(|slot| slot.is_changed())
            })
        })
    }
}

/// Hook to discover additional affected senders and augment changed account balances.
///
/// Seismic uses this to refresh token-only affected holders and report registry-backed
/// aggregate balances for promotion/demotion. It runs in the ordered maintenance loop
/// on new blocks/reorgs and does not affect transaction validation/admission.
pub trait ChangedAccountsHook: Send + Sync + 'static {
    /// Error returned when the additional account state cannot be read or transformed.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find pooled senders affected by storage changes but potentially absent from
    /// the native changed-account list. The supplied state is the new canonical tip,
    /// even when `changes` also includes a removed reorg branch.
    ///
    /// On error, maintenance conservatively marks all pooled senders dirty and
    /// withholds the candidate batch, since discovery may be incomplete.
    fn affected_accounts(
        &self,
        _state: &dyn StateProvider,
        _changes: &dyn CanonicalStorageChanges,
        _pooled_senders: &HashSet<Address>,
    ) -> Result<HashSet<Address>, Self::Error> {
        Ok(HashSet::new())
    }

    /// Transforms account balances in place. Implementations may read additional
    /// state (e.g. ERC-20 storage), but must preserve account addresses and nonces.
    ///
    /// The [`StateProvider`] is the same snapshot the maintenance loop used to
    /// load native balance/nonce, so implementations always see a consistent
    /// view of the chain.
    ///
    /// On error, maintenance discards the entire batch of account updates and
    /// requeues its addresses for reload. Required read failures must propagate
    /// rather than produce zero balances or partially augmented successful updates.
    fn transform(
        &self,
        state: &dyn StateProvider,
        accounts: &mut [ChangedAccount],
    ) -> Result<(), Self::Error>;
}

/// No-op implementation for chains that don't need balance augmentation.
impl ChangedAccountsHook for () {
    type Error = Infallible;

    fn transform(
        &self,
        _state: &dyn StateProvider,
        _accounts: &mut [ChangedAccount],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Applies an augmentation atomically from maintenance's perspective. Failed batches
/// are withheld from pool updates and remain dirty; canonical bookkeeping can continue.
fn transform_changed_accounts<H: ChangedAccountsHook>(
    hook: &H,
    state: Result<StateProviderBox, ProviderError>,
    accounts: &mut Vec<ChangedAccount>,
    dirty_addresses: &mut HashSet<Address>,
) {
    if accounts.is_empty() {
        return
    }

    let success = match state {
        Ok(state) => match hook.transform(&*state, accounts) {
            Ok(()) => true,
            Err(err) => {
                debug!(target: "txpool", %err, "failed to augment account balances; deferring updates");
                false
            }
        },
        Err(err) => {
            debug!(target: "txpool", %err, "failed to obtain account snapshot; deferring updates");
            false
        }
    };

    if success {
        for account in accounts.iter() {
            dirty_addresses.remove(&account.address);
        }
    } else {
        dirty_addresses.extend(accounts.drain(..).map(|account| account.address));
    }
}

/// Extends native records with storage-affected pooled holders, loading added holders
/// and augmenting all records from one new-head snapshot. Discovery failures cannot
/// safely identify affected senders, so they conservatively dirty every pooled sender.
fn refresh_canonical_accounts<H: ChangedAccountsHook>(
    hook: &H,
    state: Result<StateProviderBox, ProviderError>,
    changes: &dyn CanonicalStorageChanges,
    pooled_senders: &HashSet<Address>,
    accounts: &mut Vec<ChangedAccount>,
    dirty_addresses: &mut HashSet<Address>,
) {
    if accounts.is_empty() && (!changes.has_storage_changes() || pooled_senders.is_empty()) {
        return
    }

    let snapshot = match state {
        Ok(snapshot) => snapshot,
        Err(err) => {
            debug!(target: "txpool", %err, "failed to obtain canonical account snapshot; deferring updates");
            dirty_addresses.extend(pooled_senders.iter().copied());
            dirty_addresses.extend(accounts.drain(..).map(|account| account.address));
            return
        }
    };
    let affected = match hook.affected_accounts(&*snapshot, changes, pooled_senders) {
        Ok(affected) => affected,
        Err(err) => {
            debug!(target: "txpool", %err, "failed to discover storage-affected senders; deferring updates");
            dirty_addresses.extend(pooled_senders.iter().copied());
            dirty_addresses.extend(accounts.drain(..).map(|account| account.address));
            return
        }
    };

    let existing = accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
    let missing = affected.difference(&existing).copied();
    let loaded = load_accounts_from_state(&*snapshot, missing);
    dirty_addresses.extend(loaded.failed_to_load);
    accounts.extend(loaded.accounts);
    transform_changed_accounts(hook, Ok(snapshot), accounts, dirty_addresses);
}

/// Returns a spawnable future for maintaining the state of the transaction pool.
pub fn maintain_transaction_pool_future<N, Client, P, St, Tasks>(
    client: Client,
    pool: P,
    events: St,
    task_spawner: Tasks,
    config: MaintainPoolConfig,
) -> BoxFuture<'static, ()>
where
    N: NodePrimitives,
    Client: StateProviderFactory
        + BlockReaderIdExt<Header = N::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = N::BlockHeader>>
        + Clone
        + 'static,
    P: TransactionPoolExt<Transaction: PoolTransaction<Consensus = N::SignedTx>> + 'static,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
    Tasks: TaskSpawner + 'static,
{
    maintain_transaction_pool_future_with_hook(client, pool, events, task_spawner, config, ())
}

/// Like [`maintain_transaction_pool_future`] but accepts a [`ChangedAccountsHook`]
/// that can transform the changed-account balances applied on new blocks and reorgs.
/// These feed the pool's promote/demote between subpools — not the transaction
/// validation path.
pub fn maintain_transaction_pool_future_with_hook<N, Client, P, St, Tasks, H>(
    client: Client,
    pool: P,
    events: St,
    task_spawner: Tasks,
    config: MaintainPoolConfig,
    hook: H,
) -> BoxFuture<'static, ()>
where
    N: NodePrimitives,
    Client: StateProviderFactory
        + BlockReaderIdExt<Header = N::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = N::BlockHeader>>
        + Clone
        + 'static,
    P: TransactionPoolExt<Transaction: PoolTransaction<Consensus = N::SignedTx>> + 'static,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
    Tasks: TaskSpawner + 'static,
    H: ChangedAccountsHook,
{
    async move {
        maintain_transaction_pool_with_hook(client, pool, events, task_spawner, config, hook).await;
    }
    .boxed()
}

/// Maintains the state of the transaction pool by handling new blocks and reorgs.
///
/// This listens for any new blocks and reorgs and updates the transaction pool's state accordingly
pub async fn maintain_transaction_pool<N, Client, P, St, Tasks>(
    client: Client,
    pool: P,
    events: St,
    task_spawner: Tasks,
    config: MaintainPoolConfig,
) where
    N: NodePrimitives,
    Client: StateProviderFactory
        + BlockReaderIdExt<Header = N::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = N::BlockHeader>>
        + Clone
        + 'static,
    P: TransactionPoolExt<Transaction: PoolTransaction<Consensus = N::SignedTx>> + 'static,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
    Tasks: TaskSpawner + 'static,
{
    maintain_transaction_pool_with_hook(client, pool, events, task_spawner, config, ()).await
}

/// Like [`maintain_transaction_pool`] but accepts a [`ChangedAccountsHook`] that
/// can transform the changed-account balances applied on new blocks and reorgs.
/// These feed the pool's promote/demote between subpools — not the transaction
/// validation path.
pub async fn maintain_transaction_pool_with_hook<N, Client, P, St, Tasks, H>(
    client: Client,
    pool: P,
    mut events: St,
    task_spawner: Tasks,
    config: MaintainPoolConfig,
    hook: H,
) where
    N: NodePrimitives,
    Client: StateProviderFactory
        + BlockReaderIdExt<Header = N::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = N::BlockHeader>>
        + Clone
        + 'static,
    P: TransactionPoolExt<Transaction: PoolTransaction<Consensus = N::SignedTx>> + 'static,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
    Tasks: TaskSpawner + 'static,
    H: ChangedAccountsHook,
{
    let metrics = MaintainPoolMetrics::default();
    let MaintainPoolConfig { max_update_depth, max_reload_accounts, .. } = config;
    // ensure the pool points to latest state
    if let Ok(Some(latest)) = client.header_by_number_or_tag(BlockNumberOrTag::Latest) {
        let latest = SealedHeader::seal_slow(latest);
        let chain_spec = client.chain_spec();
        let info = BlockInfo {
            block_gas_limit: latest.gas_limit(),
            last_seen_block_hash: latest.hash(),
            last_seen_block_number: latest.number(),
            pending_basefee: chain_spec
                .next_block_base_fee(latest.header(), latest.timestamp_seconds())
                .unwrap_or_default(),
            pending_blob_fee: latest.maybe_next_block_blob_fee(
                chain_spec.blob_params_at_timestamp(latest.timestamp_seconds()),
            ),
        };
        pool.set_block_info(info);
    }

    // keeps track of mined blob transaction so we can clean finalized transactions
    let mut blob_store_tracker = BlobStoreCanonTracker::default();

    // keeps track of the latest finalized block
    let mut last_finalized_block =
        FinalizedBlockTracker::new(client.finalized_block_number().ok().flatten());

    // keeps track of any dirty accounts that we know of are out of sync with the pool
    let mut dirty_addresses = HashSet::default();

    // keeps track of the state of the pool wrt to blocks
    let mut maintained_state = MaintainedPoolState::InSync;

    // the future that reloads accounts from state
    let mut reload_accounts_fut = Fuse::terminated();

    // eviction interval for stale non local txs
    let mut stale_eviction_interval = time::interval(config.max_tx_lifetime);

    // toggle for the first notification
    let mut first_event = true;

    // The update loop that waits for new blocks and reorgs and performs pool updated
    // Listen for new chain events and derive the update action for the pool
    loop {
        trace!(target: "txpool", state=?maintained_state, "awaiting new block or reorg");

        metrics.set_dirty_accounts_len(dirty_addresses.len());
        let pool_info = pool.block_info();

        // after performing a pool update after a new block we have some time to properly update
        // dirty accounts and correct if the pool drifted from current state, for example after
        // restart or a pipeline run
        if maintained_state.is_drifted() {
            metrics.inc_drift();
            // assuming all senders are dirty
            dirty_addresses = pool.unique_senders();
            // make sure we toggle the state back to in sync
            maintained_state = MaintainedPoolState::InSync;
        }

        // if we have accounts that are out of sync with the pool, we reload them in chunks
        if !dirty_addresses.is_empty() && reload_accounts_fut.is_terminated() {
            let (tx, rx) = oneshot::channel();
            let c = client.clone();
            let at = pool_info.last_seen_block_hash;
            let fut = if dirty_addresses.len() > max_reload_accounts {
                // need to chunk accounts to reload
                let accs_to_reload =
                    dirty_addresses.iter().copied().take(max_reload_accounts).collect::<Vec<_>>();
                for acc in &accs_to_reload {
                    // make sure we remove them from the dirty set
                    dirty_addresses.remove(acc);
                }
                async move {
                    let res = load_accounts(c, at, accs_to_reload.into_iter());
                    let _ = tx.send((at, res));
                }
                .boxed()
            } else {
                // can fetch all dirty accounts at once
                let accs_to_reload = std::mem::take(&mut dirty_addresses);
                async move {
                    let res = load_accounts(c, at, accs_to_reload.into_iter());
                    let _ = tx.send((at, res));
                }
                .boxed()
            };
            reload_accounts_fut = rx.fuse();
            task_spawner.spawn_blocking(fut);
        }

        // check if we have a new finalized block
        if let Some(finalized) =
            last_finalized_block.update(client.finalized_block_number().ok().flatten())
        {
            if let BlobStoreUpdates::Finalized(blobs) =
                blob_store_tracker.on_finalized_block(finalized)
            {
                metrics.inc_deleted_tracked_blobs(blobs.len());
                // remove all finalized blobs from the blob store
                pool.delete_blobs(blobs);
                // and also do periodic cleanup
                let pool = pool.clone();
                task_spawner.spawn_blocking(Box::pin(async move {
                    debug!(target: "txpool", finalized_block = %finalized, "cleaning up blob store");
                    pool.cleanup_blobs();
                }));
            }
        }

        // outcomes of the futures we are waiting on
        let mut event = None;
        let mut reloaded = None;

        // select of account reloads and new canonical state updates which should arrive at the rate
        // of the block time
        tokio::select! {
            res = &mut reload_accounts_fut =>  {
                reloaded = Some(res);
            }
            ev = events.next() =>  {
                 if ev.is_none() {
                    // the stream ended, we are done
                    break;
                }
                event = ev;
                // on receiving the first event on start up, mark the pool as drifted to explicitly
                // trigger revalidation and clear out outdated txs.
                if first_event {
                    maintained_state = MaintainedPoolState::Drifted;
                    first_event = false
                }
            }
            _ = stale_eviction_interval.tick() => {
                let stale_txs: Vec<_> = pool
                    .queued_transactions()
                    .into_iter()
                    .filter(|tx| {
                        // filter stale transactions based on config
                        (tx.origin.is_external() || config.no_local_exemptions) && tx.timestamp.elapsed() > config.max_tx_lifetime
                    })
                    .map(|tx| *tx.hash())
                    .collect();
                debug!(target: "txpool", count=%stale_txs.len(), "removing stale transactions");
                pool.remove_transactions(stale_txs);
            }
        }
        // handle the result of the account reload
        match reloaded {
            Some(Ok((at, Ok(loaded)))) => {
                let accounts = loaded.into_updates(
                    at,
                    pool_info.last_seen_block_hash,
                    &hook,
                    |at| client.history_by_block_hash(at),
                    &mut dirty_addresses,
                );
                pool.update_accounts(accounts);
            }
            Some(Ok((_, Err(res)))) => {
                // Failed to load accounts from state
                let (accs, err) = *res;
                debug!(target: "txpool", %err, "failed to load accounts");
                dirty_addresses.extend(accs);
            }
            Some(Err(_)) => {
                // failed to receive the accounts, sender dropped, only possible if task panicked
                maintained_state = MaintainedPoolState::Drifted;
            }
            None => {}
        }

        // handle the new block or reorg
        let Some(event) = event else { continue };
        match event {
            CanonStateNotification::Reorg { old, new } => {
                let (old_blocks, old_state) = old.inner();
                let (new_blocks, new_state) = new.inner();
                let new_tip = new_blocks.tip();
                let new_first = new_blocks.first();
                let old_first = old_blocks.first();

                // check if the reorg is not canonical with the pool's block
                if !(old_first.parent_hash() == pool_info.last_seen_block_hash ||
                    new_first.parent_hash() == pool_info.last_seen_block_hash)
                {
                    // the new block points to a higher block than the oldest block in the old chain
                    maintained_state = MaintainedPoolState::Drifted;
                }

                let chain_spec = client.chain_spec();

                // fees for the next block: `new_tip+1`
                let pending_block_base_fee = chain_spec
                    .next_block_base_fee(new_tip.header(), new_tip.timestamp_seconds())
                    .unwrap_or_default();
                let pending_block_blob_fee = new_tip.header().maybe_next_block_blob_fee(
                    chain_spec.blob_params_at_timestamp(new_tip.timestamp_seconds()),
                );

                // we know all changed account in the new chain
                let new_changed_accounts: HashSet<_> =
                    new_state.changed_accounts().map(ChangedAccountEntry).collect();

                // find all accounts that were changed in the old chain but _not_ in the new chain
                let missing_changed_acc = old_state
                    .accounts_iter()
                    .map(|(a, _)| a)
                    .filter(|addr| !new_changed_accounts.contains(addr));

                // for these we need to fetch the nonce+balance from the db at the new tip
                let mut changed_accounts =
                    match load_accounts(client.clone(), new_tip.hash(), missing_changed_acc) {
                        Ok(LoadedAccounts { accounts, failed_to_load }) => {
                            // extend accounts we failed to load from database
                            dirty_addresses.extend(failed_to_load);

                            accounts
                        }
                        Err(err) => {
                            let (addresses, err) = *err;
                            debug!(
                                target: "txpool",
                                %err,
                                "failed to load missing changed accounts at new tip: {:?}",
                                new_tip.hash()
                            );
                            dirty_addresses.extend(addresses);
                            vec![]
                        }
                    };

                // also include all accounts from new chain
                // we can use extend here because they are unique
                changed_accounts.extend(new_changed_accounts.into_iter().map(|entry| entry.0));
                refresh_canonical_accounts(
                    &hook,
                    client.history_by_block_hash(new_tip.hash()),
                    &CanonicalStorageChangeView { new: new_state, old: Some(old_state) },
                    &pool.unique_senders(),
                    &mut changed_accounts,
                    &mut dirty_addresses,
                );

                // all transactions mined in the new chain
                let new_mined_transactions: HashSet<_> = new_blocks.transaction_hashes().collect();

                // update the pool then re-inject the pruned transactions
                // find all transactions that were mined in the old chain but not in the new chain
                let pruned_old_transactions = old_blocks
                    .transactions_ecrecovered()
                    .filter(|tx| !new_mined_transactions.contains(tx.tx_hash()))
                    .filter_map(|tx| {
                        if tx.is_eip4844() {
                            // reorged blobs no longer include the blob, which is necessary for
                            // validating the transaction. Even though the transaction could have
                            // been validated previously, we still need the blob in order to
                            // accurately set the transaction's
                            // encoded-length which is propagated over the network.
                            pool.get_blob(*tx.tx_hash())
                                .ok()
                                .flatten()
                                .map(Arc::unwrap_or_clone)
                                .and_then(|sidecar| {
                                    <P as TransactionPool>::Transaction::try_from_eip4844(
                                        tx, sidecar,
                                    )
                                })
                        } else {
                            <P as TransactionPool>::Transaction::try_from_consensus(tx).ok()
                        }
                    })
                    .collect::<Vec<_>>();

                // update the pool first
                let update = CanonicalStateUpdate {
                    new_tip: new_tip.sealed_block(),
                    pending_block_base_fee,
                    pending_block_blob_fee,
                    changed_accounts,
                    // all transactions mined in the new chain need to be removed from the pool
                    mined_transactions: new_blocks.transaction_hashes().collect(),
                    update_kind: PoolUpdateKind::Reorg,
                };
                pool.on_canonical_state_change(update);

                // all transactions that were mined in the old chain but not in the new chain need
                // to be re-injected
                //
                // Note: we no longer know if the tx was local or external
                // Because the transactions are not finalized, the corresponding blobs are still in
                // blob store (if we previously received them from the network)
                metrics.inc_reinserted_transactions(pruned_old_transactions.len());
                let _ = pool.add_external_transactions(pruned_old_transactions).await;

                // keep track of new mined blob transactions
                blob_store_tracker.add_new_chain_blocks(&new_blocks);
            }
            CanonStateNotification::Commit { new } => {
                let (blocks, state) = new.inner();
                let tip = blocks.tip();
                let chain_spec = client.chain_spec();

                // fees for the next block: `tip+1`
                let pending_block_base_fee = chain_spec
                    .next_block_base_fee(tip.header(), tip.timestamp_seconds())
                    .unwrap_or_default();
                let pending_block_blob_fee = tip.header().maybe_next_block_blob_fee(
                    chain_spec.blob_params_at_timestamp(tip.timestamp_seconds()),
                );

                let first_block = blocks.first();
                trace!(
                    target: "txpool",
                    first = first_block.number(),
                    tip = tip.number(),
                    pool_block = pool_info.last_seen_block_number,
                    "update pool on new commit"
                );

                // check if the depth is too large and should be skipped, this could happen after
                // initial sync or long re-sync
                let depth = tip.number().abs_diff(pool_info.last_seen_block_number);
                if depth > max_update_depth {
                    maintained_state = MaintainedPoolState::Drifted;
                    debug!(target: "txpool", ?depth, "skipping deep canonical update");
                    let info = BlockInfo {
                        block_gas_limit: tip.header().gas_limit(),
                        last_seen_block_hash: tip.hash(),
                        last_seen_block_number: tip.number(),
                        pending_basefee: pending_block_base_fee,
                        pending_blob_fee: pending_block_blob_fee,
                    };
                    pool.set_block_info(info);

                    // keep track of mined blob transactions
                    blob_store_tracker.add_new_chain_blocks(&blocks);

                    continue
                }

                let mut changed_accounts = Vec::with_capacity(state.state().len());
                changed_accounts.extend(state.changed_accounts());
                refresh_canonical_accounts(
                    &hook,
                    client.history_by_block_hash(tip.hash()),
                    &CanonicalStorageChangeView { new: state, old: None },
                    &pool.unique_senders(),
                    &mut changed_accounts,
                    &mut dirty_addresses,
                );

                let mined_transactions = blocks.transaction_hashes().collect();

                // check if the range of the commit is canonical with the pool's block
                if first_block.parent_hash() != pool_info.last_seen_block_hash {
                    // we received a new canonical chain commit but the commit is not canonical with
                    // the pool's block, this could happen after initial sync or
                    // long re-sync
                    maintained_state = MaintainedPoolState::Drifted;
                }

                // Canonical update
                let update = CanonicalStateUpdate {
                    new_tip: tip.sealed_block(),
                    pending_block_base_fee,
                    pending_block_blob_fee,
                    changed_accounts,
                    mined_transactions,
                    update_kind: PoolUpdateKind::Commit,
                };
                pool.on_canonical_state_change(update);

                // keep track of mined blob transactions
                blob_store_tracker.add_new_chain_blocks(&blocks);
            }
        }
    }
}

struct FinalizedBlockTracker {
    last_finalized_block: Option<BlockNumber>,
}

impl FinalizedBlockTracker {
    const fn new(last_finalized_block: Option<BlockNumber>) -> Self {
        Self { last_finalized_block }
    }

    /// Updates the tracked finalized block and returns the new finalized block if it changed
    fn update(&mut self, finalized_block: Option<BlockNumber>) -> Option<BlockNumber> {
        let finalized = finalized_block?;
        self.last_finalized_block
            .replace(finalized)
            .is_none_or(|last| last < finalized)
            .then_some(finalized)
    }
}

/// Keeps track of the pool's state, whether the accounts in the pool are in sync with the actual
/// state.
#[derive(Debug, PartialEq, Eq)]
enum MaintainedPoolState {
    /// Pool is assumed to be in sync with the current state
    InSync,
    /// Pool could be out of sync with the state
    Drifted,
}

impl MaintainedPoolState {
    /// Returns `true` if the pool is assumed to be out of sync with the current state.
    #[inline]
    const fn is_drifted(&self) -> bool {
        matches!(self, Self::Drifted)
    }
}

/// A unique [`ChangedAccount`] identified by its address that can be used for deduplication
#[derive(Eq)]
struct ChangedAccountEntry(ChangedAccount);

impl PartialEq for ChangedAccountEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.address == other.0.address
    }
}

impl Hash for ChangedAccountEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.address.hash(state);
    }
}

impl Borrow<Address> for ChangedAccountEntry {
    fn borrow(&self) -> &Address {
        &self.0.address
    }
}

#[derive(Default)]
struct LoadedAccounts {
    /// All accounts that were loaded
    accounts: Vec<ChangedAccount>,
    /// All accounts that failed to load
    failed_to_load: Vec<Address>,
}

impl LoadedAccounts {
    /// Prepares only complete, current-head account updates. Stale reloads never
    /// obtain an augmentation snapshot or overwrite newer pool balances/nonces.
    fn into_updates<H: ChangedAccountsHook>(
        self,
        at: BlockHash,
        current_head: BlockHash,
        hook: &H,
        state: impl FnOnce(BlockHash) -> Result<StateProviderBox, ProviderError>,
        dirty_addresses: &mut HashSet<Address>,
    ) -> Vec<ChangedAccount> {
        let Self { mut accounts, failed_to_load } = self;
        dirty_addresses.extend(failed_to_load);
        if at != current_head {
            dirty_addresses.extend(accounts.into_iter().map(|account| account.address));
            return Vec::new()
        }

        if !accounts.is_empty() {
            transform_changed_accounts(hook, state(at), &mut accounts, dirty_addresses);
        }
        accounts
    }
}

/// Loads all accounts at the given state
///
/// Returns an error with all given addresses if the state is not available.
///
/// Note: this expects _unique_ addresses
fn load_accounts<Client, I>(
    client: Client,
    at: BlockHash,
    addresses: I,
) -> Result<LoadedAccounts, Box<(HashSet<Address>, ProviderError)>>
where
    I: IntoIterator<Item = Address>,
    Client: StateProviderFactory,
{
    let addresses = addresses.into_iter();
    let state = match client.history_by_block_hash(at) {
        Ok(state) => state,
        Err(err) => return Err(Box::new((addresses.collect(), err))),
    };
    Ok(load_accounts_from_state(&*state, addresses))
}

/// Reload holders from the same snapshot used for registry discovery and augmentation.
fn load_accounts_from_state<S: AccountReader + ?Sized>(
    state: &S,
    addresses: impl IntoIterator<Item = Address>,
) -> LoadedAccounts {
    let mut res = LoadedAccounts::default();
    for addr in addresses {
        if let Ok(maybe_acc) = state.basic_account(&addr) {
            let acc = maybe_acc
                .map(|acc| ChangedAccount { address: addr, nonce: acc.nonce, balance: acc.balance })
                .unwrap_or_else(|| ChangedAccount::empty(addr));
            res.accounts.push(acc)
        } else {
            // failed to load account.
            res.failed_to_load.push(addr);
        }
    }
    res
}

/// Loads transactions from a file, decodes them from the JSON or RLP format, and
/// inserts them into the transaction pool on node boot up.
/// The file is removed after the transactions have been successfully processed.
async fn load_and_reinsert_transactions<P>(
    pool: P,
    file_path: &Path,
) -> Result<(), TransactionsBackupError>
where
    P: TransactionPool<Transaction: PoolTransaction<Consensus: SignedTransaction>>,
{
    if !file_path.exists() {
        return Ok(())
    }

    debug!(target: "txpool", txs_file =?file_path, "Check local persistent storage for saved transactions");
    let data = reth_fs_util::read(file_path)?;

    if data.is_empty() {
        return Ok(())
    }

    let pool_transactions: Vec<(TransactionOrigin, <P as TransactionPool>::Transaction)> =
        if let Ok(tx_backups) = serde_json::from_slice::<Vec<TxBackup>>(&data) {
            tx_backups
                .into_iter()
                .filter_map(|backup| {
                    let tx_signed = <P::Transaction as PoolTransaction>::Consensus::decode_2718(
                        &mut backup.rlp.as_ref(),
                    )
                    .ok()?;
                    let recovered = tx_signed.try_into_recovered().ok()?;
                    let pool_tx =
                        <P::Transaction as PoolTransaction>::try_from_consensus(recovered).ok()?;

                    Some((backup.origin, pool_tx))
                })
                .collect()
        } else {
            let txs_signed: Vec<<P::Transaction as PoolTransaction>::Consensus> =
                alloy_rlp::Decodable::decode(&mut data.as_slice())?;

            txs_signed
                .into_iter()
                .filter_map(|tx| tx.try_into_recovered().ok())
                .filter_map(|tx| {
                    <P::Transaction as PoolTransaction>::try_from_consensus(tx)
                        .ok()
                        .map(|pool_tx| (TransactionOrigin::Local, pool_tx))
                })
                .collect()
        };

    let inserted = futures_util::future::join_all(
        pool_transactions.into_iter().map(|(origin, tx)| pool.add_transaction(origin, tx)),
    )
    .await;

    info!(target: "txpool", txs_file =?file_path, num_txs=%inserted.len(), "Successfully reinserted local transactions from file");
    reth_fs_util::remove_file(file_path)?;
    Ok(())
}

fn save_local_txs_backup<P>(pool: P, file_path: &Path)
where
    P: TransactionPool<Transaction: PoolTransaction<Consensus: Encodable>>,
{
    let local_transactions = pool.get_local_transactions();
    if local_transactions.is_empty() {
        trace!(target: "txpool", "no local transactions to save");
        return
    }

    let local_transactions = local_transactions
        .into_iter()
        .map(|tx| {
            let consensus_tx = tx.transaction.clone_into_consensus().into_inner();
            let rlp_data = consensus_tx.encoded_2718();

            TxBackup { rlp: rlp_data.into(), origin: tx.origin }
        })
        .collect::<Vec<_>>();

    let json_data = match serde_json::to_string(&local_transactions) {
        Ok(data) => data,
        Err(err) => {
            warn!(target: "txpool", %err, txs_file=?file_path, "failed to serialize local transactions to json");
            return
        }
    };

    info!(target: "txpool", txs_file =?file_path, num_txs=%local_transactions.len(), "Saving current local transactions");
    let parent_dir = file_path.parent().map(std::fs::create_dir_all).transpose();

    match parent_dir.map(|_| reth_fs_util::write(file_path, json_data)) {
        Ok(_) => {
            info!(target: "txpool", txs_file=?file_path, "Wrote local transactions to file");
        }
        Err(err) => {
            warn!(target: "txpool", %err, txs_file=?file_path, "Failed to write local transactions to file");
        }
    }
}

/// A transaction backup that is saved as json to a file for
/// reinsertion into the pool
#[derive(Debug, Deserialize, Serialize)]
pub struct TxBackup {
    /// Encoded transaction
    pub rlp: Bytes,
    /// The origin of the transaction
    pub origin: TransactionOrigin,
}

/// Errors possible during txs backup load and decode
#[derive(thiserror::Error, Debug)]
pub enum TransactionsBackupError {
    /// Error during RLP decoding of transactions
    #[error("failed to apply transactions backup. Encountered RLP decode error: {0}")]
    Decode(#[from] alloy_rlp::Error),
    /// Error during json decoding of transactions
    #[error("failed to apply transactions backup. Encountered JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
    /// Error during file upload
    #[error("failed to apply transactions backup. Encountered file error: {0}")]
    FsPath(#[from] FsPathError),
    /// Error adding transactions to the transaction pool
    #[error("failed to insert transactions to the transactions pool. Encountered pool error: {0}")]
    Pool(#[from] PoolError),
}

/// Task which manages saving local transactions to the persistent file in case of shutdown.
/// Reloads the transactions from the file on the boot up and inserts them into the pool.
pub async fn backup_local_transactions_task<P>(
    shutdown: reth_tasks::shutdown::GracefulShutdown,
    pool: P,
    config: LocalTransactionBackupConfig,
) where
    P: TransactionPool<Transaction: PoolTransaction<Consensus: SignedTransaction>> + Clone,
{
    let Some(transactions_path) = config.transactions_path else {
        // nothing to do
        return
    };

    if let Err(err) = load_and_reinsert_transactions(pool.clone(), &transactions_path).await {
        error!(target: "txpool", "{}", err)
    }

    let graceful_guard = shutdown.await;

    // write transactions to disk
    save_local_txs_backup(pool, &transactions_path);

    drop(graceful_guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
        CoinbaseTipOrdering, EthPooledTransaction, Pool, TransactionOrigin,
    };
    use alloy_eips::eip2718::Decodable2718;
    use alloy_primitives::{hex, FlaggedStorage, U256};
    use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives, PooledTransactionVariant};
    use reth_execution_types::{Chain, ExecutionOutcome};
    use reth_fs_util as fs;
    use reth_primitives_traits::{Account, Block as _};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_tasks::TaskManager;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct TestBalanceHook {
        fail: AtomicBool,
        calls: Arc<AtomicUsize>,
        extra: HashSet<Address>,
        fail_discovery: AtomicBool,
        discovery_calls: AtomicUsize,
    }

    impl ChangedAccountsHook for TestBalanceHook {
        type Error = ProviderError;

        fn affected_accounts(
            &self,
            _state: &dyn StateProvider,
            _changes: &dyn CanonicalStorageChanges,
            pooled_senders: &HashSet<Address>,
        ) -> Result<HashSet<Address>, Self::Error> {
            self.discovery_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_discovery.load(Ordering::Relaxed) {
                return Err(ProviderError::InvalidStorageOutput)
            }
            Ok(self.extra.intersection(pooled_senders).copied().collect())
        }

        fn transform(
            &self,
            _state: &dyn StateProvider,
            accounts: &mut [ChangedAccount],
        ) -> Result<(), Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            for account in accounts {
                account.balance = account.balance.saturating_add(U256::from(100));
                // Deliberately mutate before failing: maintenance must discard even
                // a partially transformed batch, not merely catch the error.
                if self.fail.load(Ordering::Relaxed) {
                    return Err(ProviderError::InvalidStorageOutput)
                }
            }
            Ok(())
        }
    }

    fn refresh_accounts() -> Vec<ChangedAccount> {
        vec![
            ChangedAccount {
                address: Address::with_last_byte(1),
                nonce: 7,
                balance: U256::from(10),
            },
            ChangedAccount {
                address: Address::with_last_byte(2),
                nonce: 9,
                balance: U256::from(20),
            },
        ]
    }

    #[test]
    fn balance_hook_success_clears_only_refreshed_dirty_accounts() {
        let hook = TestBalanceHook::default();
        let mut accounts = refresh_accounts();
        let unrelated = Address::with_last_byte(3);
        let mut dirty = accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
        dirty.insert(unrelated);

        transform_changed_accounts(
            &hook,
            Ok(Box::new(MockEthProvider::default())),
            &mut accounts,
            &mut dirty,
        );

        let expected = refresh_accounts()
            .into_iter()
            .map(|mut account| {
                account.balance += U256::from(100);
                account
            })
            .collect::<Vec<_>>();
        assert_eq!(accounts, expected);
        assert_eq!(dirty, HashSet::from([unrelated]));
    }

    #[test]
    fn balance_hook_failure_discards_partial_batch_and_requeues_every_sender() {
        let hook = TestBalanceHook::default();
        hook.fail.store(true, Ordering::Relaxed);
        let mut accounts = refresh_accounts();
        let expected_dirty = accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
        let mut dirty = HashSet::new();

        transform_changed_accounts(
            &hook,
            Ok(Box::new(MockEthProvider::default())),
            &mut accounts,
            &mut dirty,
        );

        assert!(accounts.is_empty());
        assert_eq!(dirty, expected_dirty);
        assert_eq!(hook.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn balance_hook_snapshot_failure_defers_native_only_records() {
        let hook = TestBalanceHook::default();
        let mut accounts = refresh_accounts();
        let expected_dirty = accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
        let mut dirty = HashSet::new();

        transform_changed_accounts(
            &hook,
            Err(ProviderError::InvalidStorageOutput),
            &mut accounts,
            &mut dirty,
        );

        assert!(accounts.is_empty());
        assert_eq!(dirty, expected_dirty);
        assert_eq!(hook.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn balance_hook_retry_reloads_native_state_before_augmenting() {
        let hook = TestBalanceHook::default();
        hook.fail.store(true, Ordering::Relaxed);
        let mut accounts = refresh_accounts();
        let provider = MockEthProvider::default();
        let head = BlockHash::with_last_byte(1);
        let mut dirty = HashSet::new();
        transform_changed_accounts(
            &hook,
            provider.history_by_block_hash(head),
            &mut accounts,
            &mut dirty,
        );

        // The retry must reload native balances/nonces, not reuse the partially
        // transformed records from the failed attempt.
        for account in refresh_accounts() {
            provider.add_account(
                account.address,
                ExtendedAccount::new(account.nonce + 1, account.balance + U256::from(5)),
            );
        }
        hook.fail.store(false, Ordering::Relaxed);
        let loaded = load_accounts(provider.clone(), head, dirty.iter().copied()).unwrap();
        let updates = loaded.into_updates(
            head,
            head,
            &hook,
            |at| provider.history_by_block_hash(at),
            &mut dirty,
        );

        assert!(dirty.is_empty());
        assert_eq!(updates.len(), 2);
        for original in refresh_accounts() {
            let updated =
                updates.iter().find(|account| account.address == original.address).unwrap();
            assert_eq!(updated.nonce, original.nonce + 1);
            assert_eq!(updated.balance, original.balance + U256::from(105));
        }
    }

    #[test]
    fn balance_hook_stale_reload_requeues_without_reading_another_snapshot() {
        let hook = TestBalanceHook::default();
        let accounts = refresh_accounts();
        let failed_native = Address::with_last_byte(3);
        let mut expected_dirty =
            accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
        expected_dirty.insert(failed_native);
        let loaded = LoadedAccounts { accounts, failed_to_load: vec![failed_native] };
        let mut dirty = HashSet::new();

        let updates = loaded.into_updates(
            BlockHash::with_last_byte(1),
            BlockHash::with_last_byte(2),
            &hook,
            |_| panic!("stale reload must not obtain an augmentation snapshot"),
            &mut dirty,
        );

        assert!(updates.is_empty());
        assert_eq!(dirty, expected_dirty);
        assert_eq!(hook.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn balance_hook_reload_failure_preserves_failed_native_senders() {
        let hook = TestBalanceHook::default();
        let accounts = refresh_accounts();
        let failed_native = Address::with_last_byte(3);
        let mut expected_dirty =
            accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
        expected_dirty.insert(failed_native);
        let loaded = LoadedAccounts { accounts, failed_to_load: vec![failed_native] };
        let head = BlockHash::with_last_byte(1);
        let mut dirty = HashSet::new();

        let updates = loaded.into_updates(
            head,
            head,
            &hook,
            |at| {
                assert_eq!(at, head);
                Err(ProviderError::InvalidStorageOutput)
            },
            &mut dirty,
        );

        assert!(updates.is_empty());
        assert_eq!(dirty, expected_dirty);
    }

    #[test]
    fn balance_hook_noop_preserves_native_accounts() {
        let mut accounts = refresh_accounts();
        let original = accounts.clone();
        let mut dirty = accounts.iter().map(|account| account.address).collect::<HashSet<_>>();
        transform_changed_accounts(
            &(),
            Ok(Box::new(MockEthProvider::default())),
            &mut accounts,
            &mut dirty,
        );
        assert_eq!(accounts, original);
        assert!(dirty.is_empty());
    }

    fn storage_outcome(
        address: Address,
        key: U256,
        original: FlaggedStorage,
        present: FlaggedStorage,
    ) -> ExecutionOutcome {
        ExecutionOutcome::new_init(
            std::iter::once((
                address,
                (
                    Some(Account::default()),
                    Some(Account::default()),
                    std::iter::once((key.to_be_bytes::<32>().into(), (original, present)))
                        .collect(),
                ),
            ))
            .collect(),
            Default::default(),
            [],
            vec![],
            1,
            vec![],
        )
    }

    #[test]
    fn canonical_storage_view_ignores_read_only_slots_but_includes_privacy_changes() {
        let token = Address::with_last_byte(0x40);
        let key = U256::from(7);
        let original = FlaggedStorage::public(U256::from(5));
        let read_only = storage_outcome(token, key, original, original);
        let view = CanonicalStorageChangeView { new: &read_only, old: None };
        assert!(!view.has_storage_changes());
        assert!(!view.storage_changed(token));
        assert!(!view.slot_changed(token, key));

        let privacy_change =
            storage_outcome(token, key, original, FlaggedStorage::new(original.value, true));
        let view = CanonicalStorageChangeView { new: &privacy_change, old: None };
        assert!(view.has_storage_changes());
        assert!(view.storage_changed(token));
        assert!(view.slot_changed(token, key));
        assert!(!view.slot_changed(token, key + U256::from(1)));
    }

    #[test]
    fn canonical_storage_view_includes_removed_and_added_reorg_branches() {
        let token = Address::with_last_byte(0x40);
        let old_key = U256::from(7);
        let new_key = U256::from(8);
        let old = storage_outcome(
            token,
            old_key,
            FlaggedStorage::ZERO,
            FlaggedStorage::public(U256::from(5)),
        );
        let new = storage_outcome(
            token,
            new_key,
            FlaggedStorage::ZERO,
            FlaggedStorage::public(U256::from(10)),
        );
        let view = CanonicalStorageChangeView { new: &new, old: Some(&old) };
        assert!(view.slot_changed(token, old_key));
        assert!(view.slot_changed(token, new_key));
        assert!(!view.slot_changed(Address::with_last_byte(0x41), old_key));
    }

    #[test]
    fn canonical_storage_view_treats_account_deletion_as_a_wipe() {
        let token = Address::with_last_byte(0x40);
        let mut outcome =
            storage_outcome(token, U256::from(7), FlaggedStorage::ZERO, FlaggedStorage::ZERO);
        let account = outcome.state_mut().state.get_mut(&token).unwrap();
        account.info = None;
        account.storage.clear();
        let view = CanonicalStorageChangeView { new: &outcome, old: None };
        assert!(view.has_storage_changes());
        assert!(view.storage_changed(token));
        assert!(view.slot_changed(token, U256::MAX));
    }

    #[test]
    fn canonical_storage_view_treats_destroyed_and_recreated_storage_as_wiped() {
        let token = Address::with_last_byte(0x40);
        let mut outcome =
            storage_outcome(token, U256::from(7), FlaggedStorage::ZERO, FlaggedStorage::ZERO);
        let account = outcome.state_mut().state.get_mut(&token).unwrap();
        account.status = account.status.on_created().on_selfdestructed().on_created();
        account.storage.clear();
        assert!(account.info.is_some());
        let view = CanonicalStorageChangeView { new: &outcome, old: None };
        assert!(view.has_storage_changes());
        assert!(view.storage_changed(token));
        assert!(view.slot_changed(token, U256::MAX));
    }

    struct FailingAccountReader {
        inner: MockEthProvider,
        failed: Address,
    }

    impl AccountReader for FailingAccountReader {
        fn basic_account(&self, address: &Address) -> Result<Option<Account>, ProviderError> {
            if *address == self.failed {
                return Err(ProviderError::InvalidStorageOutput)
            }
            self.inner.basic_account(address)
        }
    }

    #[test]
    fn holder_reload_distinguishes_absent_accounts_from_failed_native_reads() {
        let alice = Address::with_last_byte(1);
        let bob = Address::with_last_byte(2);
        let absent = Address::with_last_byte(3);
        let state = FailingAccountReader { inner: MockEthProvider::default(), failed: bob };
        state.inner.add_account(alice, ExtendedAccount::new(7, U256::from(10)));
        let loaded = load_accounts_from_state(&state, [alice, bob, absent]);
        assert_eq!(loaded.failed_to_load, vec![bob]);
        assert_eq!(
            loaded.accounts,
            vec![
                ChangedAccount { address: alice, nonce: 7, balance: U256::from(10) },
                ChangedAccount::empty(absent),
            ]
        );
    }

    #[test]
    fn canonical_refresh_adds_token_only_holders_and_deduplicates_native_records() {
        let originals = refresh_accounts();
        let pooled = originals.iter().map(|account| account.address).collect::<HashSet<_>>();
        let hook = TestBalanceHook { extra: pooled.clone(), ..Default::default() };
        let provider = MockEthProvider::default();
        // Alice already has a native record. It must be kept, not duplicated or
        // replaced with a second read. Bob needs native/nonce loaded from this snapshot.
        for account in &originals {
            provider
                .add_account(account.address, ExtendedAccount::new(account.nonce, account.balance));
        }
        let alice = *originals.first().unwrap();
        provider.add_account(alice.address, ExtendedAccount::new(99, U256::from(999)));
        let mut records = vec![alice];
        let changes = storage_outcome(
            Address::with_last_byte(0x40),
            U256::from(7),
            FlaggedStorage::ZERO,
            FlaggedStorage::public(U256::from(5)),
        );
        let mut dirty = pooled.clone();
        refresh_canonical_accounts(
            &hook,
            Ok(Box::new(provider)),
            &CanonicalStorageChangeView { new: &changes, old: None },
            &pooled,
            &mut records,
            &mut dirty,
        );
        assert!(dirty.is_empty());
        assert_eq!(records.len(), 2);
        for native in originals {
            assert_eq!(
                records.iter().find(|account| account.address == native.address),
                Some(&ChangedAccount { balance: native.balance + U256::from(100), ..native })
            );
        }
    }

    #[test]
    fn canonical_discovery_failure_dirties_all_pooled_senders_and_withholds_native_records() {
        let hook = TestBalanceHook::default();
        hook.fail_discovery.store(true, Ordering::Relaxed);
        let pooled = HashSet::from([Address::with_last_byte(1), Address::with_last_byte(2)]);
        let unrelated = Address::with_last_byte(3);
        let mut records = vec![ChangedAccount::empty(unrelated)];
        let changes = storage_outcome(
            Address::with_last_byte(0x40),
            U256::from(7),
            FlaggedStorage::ZERO,
            FlaggedStorage::public(U256::from(5)),
        );
        let mut dirty = HashSet::new();
        refresh_canonical_accounts(
            &hook,
            Ok(Box::new(MockEthProvider::default())),
            &CanonicalStorageChangeView { new: &changes, old: None },
            &pooled,
            &mut records,
            &mut dirty,
        );
        assert!(records.is_empty());
        let mut expected = pooled;
        expected.insert(unrelated);
        assert_eq!(dirty, expected);
        assert_eq!(hook.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn canonical_snapshot_failure_dirties_token_only_holders_even_without_native_changes() {
        let hook = TestBalanceHook::default();
        let pooled = HashSet::from([Address::with_last_byte(1), Address::with_last_byte(2)]);
        let mut records = vec![];
        let changes = storage_outcome(
            Address::with_last_byte(0x40),
            U256::from(7),
            FlaggedStorage::ZERO,
            FlaggedStorage::public(U256::from(5)),
        );
        let mut dirty = HashSet::new();
        refresh_canonical_accounts(
            &hook,
            Err(ProviderError::InvalidStorageOutput),
            &CanonicalStorageChangeView { new: &changes, old: None },
            &pooled,
            &mut records,
            &mut dirty,
        );
        assert!(records.is_empty());
        assert_eq!(dirty, pooled);
        assert_eq!(hook.discovery_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn canonical_transform_failure_requeues_added_holders_too() {
        let originals = refresh_accounts();
        let pooled = originals.iter().map(|account| account.address).collect::<HashSet<_>>();
        let hook = TestBalanceHook { extra: pooled.clone(), ..Default::default() };
        hook.fail.store(true, Ordering::Relaxed);
        let provider = MockEthProvider::default();
        for account in &originals {
            provider
                .add_account(account.address, ExtendedAccount::new(account.nonce, account.balance));
        }
        let changes = storage_outcome(
            Address::with_last_byte(0x40),
            U256::from(7),
            FlaggedStorage::ZERO,
            FlaggedStorage::public(U256::from(5)),
        );
        let mut records = vec![];
        let mut dirty = HashSet::new();
        refresh_canonical_accounts(
            &hook,
            Ok(Box::new(provider)),
            &CanonicalStorageChangeView { new: &changes, old: None },
            &pooled,
            &mut records,
            &mut dirty,
        );
        assert!(records.is_empty());
        assert_eq!(dirty, pooled);
    }

    #[test]
    fn canonical_refresh_skips_discovery_without_records_or_storage_changes() {
        let hook = TestBalanceHook::default();
        let outcome: ExecutionOutcome = ExecutionOutcome::default();
        let mut records = vec![];
        let mut dirty = HashSet::new();
        refresh_canonical_accounts(
            &hook,
            Err(ProviderError::InvalidStorageOutput),
            &CanonicalStorageChangeView { new: &outcome, old: None },
            &HashSet::from([Address::with_last_byte(1)]),
            &mut records,
            &mut dirty,
        );
        assert!(dirty.is_empty());
        assert_eq!(hook.discovery_calls.load(Ordering::Relaxed), 0);
    }

    async fn failed_hook_preserves_canonical_bookkeeping(reorg: bool) {
        let tx_bytes = hex!(
            "02f87201830655c2808505ef61f08482565f94388c818ca8b9251b393131c08a736a67ccb192978801049e39c4b5b1f580c001a01764ace353514e8abdfb92446de356b260e3c1225b73fc4c8876a6258d12a129a04f02294aa61ca7676061cd99f29275491218b4754b46a0248e5e42bc5091f507"
        );
        let tx = PooledTransactionVariant::decode_2718(&mut &tx_bytes[..]).unwrap();
        let transaction = EthPooledTransaction::from_pooled(tx.try_into_recovered().unwrap());
        let sender = transaction.sender();
        let tx_hash = *transaction.hash();
        let native = Account { nonce: 42, balance: U256::MAX, ..Default::default() };
        let provider = MockEthProvider::default();
        provider.add_account(sender, ExtendedAccount::new(native.nonce, native.balance));
        let blobs = InMemoryBlobStore::default();
        let validator = EthTransactionValidatorBuilder::new(provider.clone()).build(blobs.clone());
        let pool = Pool::new(validator, CoinbaseTipOrdering::default(), blobs, Default::default());
        let consensus_tx = transaction.clone_into_consensus().into_inner();
        pool.add_transaction(TransactionOrigin::Local, transaction).await.unwrap();
        assert!(pool.get(&tx_hash).is_some());

        let block = Block {
            header: alloy_consensus::Header {
                number: 1,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            body: BlockBody { transactions: vec![consensus_tx], ..Default::default() },
        }
        .seal_slow()
        .try_recover()
        .unwrap();
        let tip_hash = block.hash();
        let outcome = ExecutionOutcome::new_init(
            std::iter::once((
                sender,
                (
                    Some(native),
                    Some(Account { nonce: 43, balance: U256::ZERO, ..Default::default() }),
                    Default::default(),
                ),
            ))
            .collect(),
            Default::default(),
            [],
            vec![vec![]],
            1,
            vec![],
        );
        let new = Arc::new(Chain::new(vec![block], outcome, None));
        let event = if reorg {
            let old_block = Block {
                header: alloy_consensus::Header {
                    number: 1,
                    timestamp: 1,
                    gas_limit: 30_000_000,
                    ..Default::default()
                },
                body: BlockBody::default(),
            }
            .seal_slow()
            .try_recover()
            .unwrap();
            CanonStateNotification::Reorg {
                old: Arc::new(Chain::new(vec![old_block], ExecutionOutcome::default(), None)),
                new,
            }
        } else {
            CanonStateNotification::Commit { new }
        };
        let hook = TestBalanceHook::default();
        hook.fail.store(true, Ordering::Relaxed);
        let calls = hook.calls.clone();
        let manager = TaskManager::new(tokio::runtime::Handle::current());

        tokio::time::timeout(
            Duration::from_secs(10),
            maintain_transaction_pool_with_hook::<EthPrimitives, _, _, _, _, _>(
                provider,
                pool.clone(),
                futures_util::stream::iter([event]),
                manager.executor(),
                MaintainPoolConfig::default(),
                hook,
            ),
        )
        .await
        .unwrap();

        assert!(calls.load(Ordering::Relaxed) >= 1);
        assert_eq!(pool.block_info().last_seen_block_hash, tip_hash);
        assert_eq!(pool.block_info().last_seen_block_number, 1);
        assert!(pool.get(&tx_hash).is_none(), "mined transaction must still be removed");
    }

    #[tokio::test]
    async fn balance_hook_commit_failure_still_updates_head_and_removes_mined_transactions() {
        failed_hook_preserves_canonical_bookkeeping(false).await;
    }

    #[tokio::test]
    async fn balance_hook_reorg_failure_still_updates_head_and_removes_mined_transactions() {
        failed_hook_preserves_canonical_bookkeeping(true).await;
    }

    #[test]
    fn changed_acc_entry() {
        let changed_acc = ChangedAccountEntry(ChangedAccount::empty(Address::random()));
        let mut copy = changed_acc.0;
        copy.nonce = 10;
        assert!(changed_acc.eq(&ChangedAccountEntry(copy)));
    }

    const EXTENSION: &str = "json";
    const FILENAME: &str = "test_transactions_backup";

    #[tokio::test(flavor = "multi_thread")]
    async fn test_save_local_txs_backup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let transactions_path = temp_dir.path().join(FILENAME).with_extension(EXTENSION);
        let tx_bytes = hex!(
            "02f87201830655c2808505ef61f08482565f94388c818ca8b9251b393131c08a736a67ccb192978801049e39c4b5b1f580c001a01764ace353514e8abdfb92446de356b260e3c1225b73fc4c8876a6258d12a129a04f02294aa61ca7676061cd99f29275491218b4754b46a0248e5e42bc5091f507"
        );
        let tx = PooledTransactionVariant::decode_2718(&mut &tx_bytes[..]).unwrap();
        let provider = MockEthProvider::default();
        let transaction = EthPooledTransaction::from_pooled(tx.try_into_recovered().unwrap());
        let tx_to_cmp = transaction.clone();
        let sender = hex!("1f9090aaE28b8a3dCeaDf281B0F12828e676c326").into();
        provider.add_account(sender, ExtendedAccount::new(42, U256::MAX));
        let blob_store = InMemoryBlobStore::default();
        let validator = EthTransactionValidatorBuilder::new(provider).build(blob_store.clone());

        let txpool = Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            blob_store.clone(),
            Default::default(),
        );

        txpool.add_transaction(TransactionOrigin::Local, transaction.clone()).await.unwrap();

        let handle = tokio::runtime::Handle::current();
        let manager = TaskManager::new(handle);
        let config = LocalTransactionBackupConfig::with_local_txs_backup(transactions_path.clone());
        manager.executor().spawn_critical_with_graceful_shutdown_signal("test task", |shutdown| {
            backup_local_transactions_task(shutdown, txpool.clone(), config)
        });

        let mut txns = txpool.get_local_transactions();
        let tx_on_finish = txns.pop().expect("there should be 1 transaction");

        assert_eq!(*tx_to_cmp.hash(), *tx_on_finish.hash());

        // shutdown the executor
        manager.graceful_shutdown();

        let data = fs::read(transactions_path).unwrap();

        let txs: Vec<TxBackup> = serde_json::from_slice::<Vec<TxBackup>>(&data).unwrap();
        assert_eq!(txs.len(), 1);

        temp_dir.close().unwrap();
    }

    #[test]
    fn test_update_with_higher_finalized_block() {
        let mut tracker = FinalizedBlockTracker::new(Some(10));
        assert_eq!(tracker.update(Some(15)), Some(15));
        assert_eq!(tracker.last_finalized_block, Some(15));
    }

    #[test]
    fn test_update_with_lower_finalized_block() {
        let mut tracker = FinalizedBlockTracker::new(Some(20));
        assert_eq!(tracker.update(Some(15)), None);
        assert_eq!(tracker.last_finalized_block, Some(15));
    }

    #[test]
    fn test_update_with_equal_finalized_block() {
        let mut tracker = FinalizedBlockTracker::new(Some(20));
        assert_eq!(tracker.update(Some(20)), None);
        assert_eq!(tracker.last_finalized_block, Some(20));
    }

    #[test]
    fn test_update_with_no_last_finalized_block() {
        let mut tracker = FinalizedBlockTracker::new(None);
        assert_eq!(tracker.update(Some(10)), Some(10));
        assert_eq!(tracker.last_finalized_block, Some(10));
    }

    #[test]
    fn test_update_with_no_new_finalized_block() {
        let mut tracker = FinalizedBlockTracker::new(Some(10));
        assert_eq!(tracker.update(None), None);
        assert_eq!(tracker.last_finalized_block, Some(10));
    }

    #[test]
    fn test_update_with_no_finalized_blocks() {
        let mut tracker = FinalizedBlockTracker::new(None);
        assert_eq!(tracker.update(None), None);
        assert_eq!(tracker.last_finalized_block, None);
    }
}
