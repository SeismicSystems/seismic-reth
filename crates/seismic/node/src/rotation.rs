//! Canonical rotation metadata and additive purpose-key fetching.
//!
//! The serialized watcher replaces the entire view from one canonical head hash.
//! Execution never publishes schedules; it only requests missing epoch material.
//! A separate polling future services those deduplicated requests even during
//! staged sync, where per-block canonical notifications are absent.

use crate::keys_source::fetch_epoch_keys;
use futures_util::StreamExt;
use reth_node_core::args::PurposeKeysArgs;
use reth_provider::{CanonStateNotificationStream, StateProviderFactory};
use reth_seismic_keys::{
    registry::{read_schedule_with, KEY_ROTATION_REGISTRY},
    CanonicalRotationView, PurposeKeyring,
};
use reth_seismic_primitives::SeismicPrimitives;
use std::{sync::Arc, time::Duration};
use tracing::{error, info, warn};

const PERIODIC_RECONCILE: Duration = Duration::from_secs(60);
const FETCH_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Keep RPC/pool metadata canonical and service missing-key requests. Fetching is
/// independent of metadata reconciliation, so a slow custodian cannot stall reorg
/// publication. Dropping the watcher (or ending its stream) cancels both futures.
pub async fn watch_key_rotations<Client>(
    client: Client,
    keyring: Arc<PurposeKeyring>,
    args: PurposeKeysArgs,
    mut events: CanonStateNotificationStream<SeismicPrimitives>,
) where
    Client: StateProviderFactory + 'static,
{
    let canonical = async {
        reconcile_view(&client, &keyring);
        let mut tick = tokio::time::interval(PERIODIC_RECONCILE);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                notification = events.next() => {
                    if notification.is_none() { return; }
                    // Re-read even for an ordinary commit: the head number and
                    // schedule must be published together, never independently.
                    reconcile_view(&client, &keyring);
                }
                _ = tick.tick() => reconcile_view(&client, &keyring),
            }
        }
    };
    let fetch = async {
        let mut tick = tokio::time::interval(FETCH_POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            fetch_missing_epochs(&keyring, &args).await;
        }
    };
    tokio::select! {
        _ = canonical => {},
        _ = fetch => {},
    }
}

/// Boot reconciliation uses a bounded fetch budget and fails startup if any
/// announced material is unavailable. Epoch zero was already fetched at boot.
pub async fn boot_reconcile<Client>(
    client: &Client,
    keyring: &PurposeKeyring,
    args: &PurposeKeysArgs,
) -> eyre::Result<()>
where
    Client: StateProviderFactory,
{
    keyring.replace_canonical_view(read_registry_view(client)?);
    for epoch in keyring.unfetched_epochs() {
        let keys = fetch_epoch_keys(args, epoch).await?;
        keyring.insert_epoch(epoch, keys)?;
    }
    Ok(())
}

fn reconcile_view<Client: StateProviderFactory>(client: &Client, keyring: &PurposeKeyring) {
    match read_registry_view(client) {
        Ok(view) => keyring.replace_canonical_view(view),
        Err(err) => {
            warn!(target: "seismic::rotation", %err, "failed to reconcile rotation registry; will retry")
        }
    }
}

/// Fetch material only. Neither a successful fetch nor an execution request may
/// publish activation metadata. Failed requests remain queued for another pass.
async fn fetch_missing_epochs(keyring: &PurposeKeyring, args: &PurposeKeysArgs) {
    for epoch in keyring.unfetched_epochs() {
        match fetch_epoch_keys(args, epoch).await {
            Ok(keys) => match keyring.insert_epoch(epoch, keys) {
                Ok(true) => info!(target: "seismic::rotation", epoch, "fetched purpose keys"),
                Ok(false) => {}
                Err(err) => {
                    error!(target: "seismic::rotation", %err, epoch, "custodian served conflicting keys; original material retained")
                }
            },
            Err(err) => {
                warn!(target: "seismic::rotation", %err, epoch, "failed to fetch purpose keys; will retry")
            }
        }
    }
    metrics::gauge!("seismic.rotation.pending_unfetched_epochs")
        .set(keyring.unfetched_epochs().len() as f64);
}

/// Pin state to one head hash, then verify it is still canonical before returning.
/// A concurrent head change causes a retry, never a mixed head/schedule publication.
fn read_registry_view<Client: StateProviderFactory>(
    client: &Client,
) -> eyre::Result<CanonicalRotationView> {
    let head = client.chain_info()?;
    let state = client.state_by_block_hash(head.best_hash)?;
    let schedule = read_schedule_with(|slot| {
        state.storage(KEY_ROTATION_REGISTRY, slot).map(|value| value.unwrap_or_default().value)
    })?;
    let current = client.chain_info()?;
    eyre::ensure!(
        current.best_hash == head.best_hash && current.best_number == head.best_number,
        "canonical head changed while reading rotation registry"
    );
    Ok(CanonicalRotationView { head_hash: head.best_hash, head_number: head.best_number, schedule })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{B256, U256};
    use alloy_seismic_evm::PurposeKeys;
    use reth_evm::{
        execute::{BlockExecutionError, BlockExecutor},
        ConfigureEvm,
    };
    use reth_node_core::args::PurposeKeysSource;
    use reth_primitives_traits::SealedBlock;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_revm::{
        db::{CacheDB, EmptyDB, State},
        state::AccountInfo,
    };
    use reth_seismic_evm::SeismicEvmConfig;
    use reth_seismic_keys::{
        registry::{rotation_entry_slot, ROTATIONS_LEN_SLOT},
        RotationEntry, RotationSchedule,
    };
    use reth_seismic_primitives::SeismicBlock;

    fn view(number: u64, activation: Option<u64>) -> CanonicalRotationView {
        CanonicalRotationView {
            head_hash: B256::from(U256::from_limbs([number, activation.unwrap_or_default(), 0, 0])),
            head_number: number,
            schedule: RotationSchedule::from_entries(activation.map(|activation_block| {
                RotationEntry { epoch: 1, activation_block, announced_at_block: 101 }
            }))
            .unwrap(),
        }
    }

    fn reconcile_fixture(keyring: &PurposeKeyring, view: CanonicalRotationView) {
        let provider = MockEthProvider::<SeismicPrimitives>::new();
        provider
            .add_header(view.head_hash, Header { number: view.head_number, ..Default::default() });
        let mut slots = vec![(ROTATIONS_LEN_SLOT, U256::from(view.schedule.len()).into())];
        slots.extend(view.schedule.entries().iter().enumerate().map(|(index, entry)| {
            (
                rotation_entry_slot(index as u64),
                U256::from_limbs([
                    entry.epoch,
                    entry.activation_block,
                    entry.announced_at_block,
                    0,
                ])
                .into(),
            )
        }));
        provider.add_account(
            KEY_ROTATION_REGISTRY,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(slots),
        );
        reconcile_view(&provider, keyring);
        assert_eq!(keyring.canonical_view(), view);
    }

    #[test]
    fn reconciliation_removes_orphan_and_accepts_equal_length_replacement() {
        let keyring = PurposeKeyring::single_epoch(PurposeKeys::well_known());
        reconcile_fixture(&keyring, view(102, Some(200)));
        reconcile_fixture(&keyring, view(102, None));
        assert_eq!(keyring.pending(), None);
        reconcile_fixture(&keyring, view(102, Some(200)));
        reconcile_fixture(&keyring, view(102, Some(300)));
        assert_eq!(keyring.pending(), Some((1, 300)));
    }

    #[test]
    fn reconciliation_accepts_lower_head() {
        let keyring = PurposeKeyring::single_epoch(PurposeKeys::well_known());
        reconcile_fixture(&keyring, view(200, Some(200)));
        reconcile_fixture(&keyring, view(100, None));
        assert_eq!(keyring.known_tip(), 100);
        assert_eq!(keyring.current().unwrap().0, 0);
        assert_eq!(keyring.canonical_view(), view(100, None));
    }

    #[test]
    fn absent_registry_reads_as_empty_schedule() {
        let provider = MockEthProvider::<SeismicPrimitives>::new();
        provider.add_header(B256::ZERO, alloy_consensus::Header::default());
        let view = read_registry_view(&provider).unwrap();
        assert!(view.schedule.is_empty());
    }

    // Same parent-state attempt used before and after the worker fetch. No
    // canonical notifications or schedule publication are needed during catch-up.
    fn execution_attempt(keyring: Arc<PurposeKeyring>) -> Result<(), BlockExecutionError> {
        let config =
            SeismicEvmConfig::new(reth_seismic_chainspec::SEISMIC_MAINNET.clone(), keyring);
        let mut parent = CacheDB::<EmptyDB>::default();
        parent.insert_account_info(KEY_ROTATION_REGISTRY, AccountInfo::default());
        parent
            .insert_account_storage(
                KEY_ROTATION_REGISTRY,
                U256::from_be_bytes(ROTATIONS_LEN_SLOT.0),
                U256::from(1).into(),
            )
            .unwrap();
        parent
            .insert_account_storage(
                KEY_ROTATION_REGISTRY,
                U256::from_be_bytes(rotation_entry_slot(0).0),
                U256::from_limbs([1, 200, 101, 0]).into(),
            )
            .unwrap();
        let mut state = State::builder().with_database(parent).build();
        let block = SealedBlock::seal_slow(SeismicBlock {
            header: Header {
                number: 200,
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::ZERO),
                ..Default::default()
            },
            body: Default::default(),
        });
        let mut executor = config.executor_for_block(&mut state, &block);
        executor.apply_pre_execution_changes()
    }

    #[tokio::test]
    async fn execution_request_fetches_without_publishing_a_schedule() {
        let keyring = Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known()));
        for _ in 0..3 {
            assert!(execution_attempt(keyring.clone()).unwrap_err().is_retryable());
        }
        assert_eq!(keyring.requested_epochs(), vec![1]);
        let args = PurposeKeysArgs { source: PurposeKeysSource::BuiltIn, ..Default::default() };
        fetch_missing_epochs(&keyring, &args).await;
        execution_attempt(keyring.clone()).unwrap();
        assert!(keyring.requested_epochs().is_empty());
        assert!(keyring.canonical_view().schedule.is_empty());
    }
}
