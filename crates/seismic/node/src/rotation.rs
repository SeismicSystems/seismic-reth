//! The purpose-key rotation watcher: keeps the [`PurposeKeyring`] in sync with the
//! on-chain `KeyRotationRegistry` and fetches newly announced epochs' keys from the
//! local key custodian (design: `docs/design/purpose-key-rotation.md` §5.3).
//!
//! Dormant by construction today: the registry predeploy has not shipped, so its
//! address reads as empty storage, the schedule stays empty, and every path here
//! no-ops. Once the contract lands in genesis (rollout Phase 1) the watcher starts
//! doing real work with no further node changes.
//!
//! The canonical-state stream is a lossy hint (it drops notifications on lag), so
//! **registry storage is the source of truth**: the watcher re-reads it at task
//! start, on every reorg, on every `RotationAnnounced` log it happens to see, and
//! unconditionally every [`RECONCILE_EVERY_N_BLOCKS`] blocks.

use crate::keys_source::fetch_epoch_keys;
use alloy_consensus::{BlockHeader, TxReceipt};
use alloy_primitives::B256;
use futures_util::StreamExt;
use reth_node_core::args::PurposeKeysArgs;
use reth_provider::{CanonStateNotification, CanonStateNotificationStream, StateProviderFactory};
use reth_seismic_keys::{
    registry::{
        decode_rotation_entry, rotation_entry_slot, KEY_ROTATION_REGISTRY, ROTATIONS_LEN_SLOT,
        ROTATION_ANNOUNCED_TOPIC,
    },
    PurposeKeyring, RotationSchedule,
};
use reth_seismic_primitives::SeismicPrimitives;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Reconcile from registry storage at least this often even without any hint, as a
/// safety net for dropped notifications.
const RECONCILE_EVERY_N_BLOCKS: u64 = 256;

/// Hard cap on the rotations array length the node will read. Rotations are rare,
/// operator-triggered events; a length beyond this is a corrupt or hostile registry.
const MAX_ROTATIONS: u64 = 100_000;

/// Background task keeping the keyring in sync with the on-chain rotation registry.
/// Spawn as a critical task; it runs until the canonical-state stream ends (node
/// shutdown).
pub async fn watch_key_rotations<Client>(
    client: Client,
    keyring: Arc<PurposeKeyring>,
    args: PurposeKeysArgs,
    mut events: CanonStateNotificationStream<SeismicPrimitives>,
) where
    Client: StateProviderFactory + 'static,
{
    // Catch up immediately: boot reconciliation ran before launch, but blocks may
    // have landed since.
    reconcile(&client, &keyring, &args).await;

    let mut blocks_since_reconcile = 0u64;
    while let Some(notification) = events.next().await {
        let Some(tip) = notification.tip_checked() else { continue };
        keyring.note_tip(tip.number());
        blocks_since_reconcile += 1;

        let reorged = matches!(notification, CanonStateNotification::Reorg { .. });
        let announced = has_rotation_announcement(&notification);
        let unfetched_pending = !keyring.unfetched_scheduled_epochs().is_empty();

        if reorged ||
            announced ||
            unfetched_pending ||
            blocks_since_reconcile >= RECONCILE_EVERY_N_BLOCKS
        {
            blocks_since_reconcile = 0;
            if announced {
                info!(target: "seismic::rotation", tip = tip.number, "observed a RotationAnnounced log; reconciling");
            }
            reconcile(&client, &keyring, &args).await;
        }
    }
}

/// One-shot boot reconciliation, run before the node launches: read the registry
/// from the latest local state and fetch every announced epoch's keys with the
/// bounded retry budget. Errors (instead of retrying indefinitely like the watcher)
/// so a boot without required key material fails fast and loud, matching the
/// epoch-0 boot-fetch policy.
pub async fn boot_reconcile<Client>(
    client: &Client,
    keyring: &PurposeKeyring,
    args: &PurposeKeysArgs,
) -> eyre::Result<()>
where
    Client: StateProviderFactory,
{
    let schedule = read_registry_schedule(client)?;
    apply_schedule_updates(keyring, &schedule);
    for epoch in keyring.unfetched_scheduled_epochs() {
        let keys = fetch_epoch_keys(args, epoch).await?;
        keyring
            .insert_epoch(epoch, keys)
            .map_err(|e| eyre::eyre!("conflicting keys for announced epoch: {e}"))?;
        info!(target: "seismic::rotation", epoch, "fetched purpose keys for announced epoch at boot");
    }
    Ok(())
}

/// One watcher reconcile pass: re-read the registry schedule from latest state,
/// merge it, fetch any missing epochs' keys, and refresh the gauge. Never fails the
/// task — failures are logged and retried on the next pass.
async fn reconcile<Client>(client: &Client, keyring: &PurposeKeyring, args: &PurposeKeysArgs)
where
    Client: StateProviderFactory,
{
    match read_registry_schedule(client) {
        Ok(schedule) => apply_schedule_updates(keyring, &schedule),
        Err(e) => {
            warn!(target: "seismic::rotation", %e, "failed to read the rotation registry; will retry")
        }
    }

    for epoch in keyring.unfetched_scheduled_epochs() {
        match fetch_epoch_keys(args, epoch).await {
            Ok(keys) => match keyring.insert_epoch(epoch, keys) {
                Ok(true) => {
                    info!(target: "seismic::rotation", epoch, "fetched purpose keys for announced epoch")
                }
                Ok(false) => {}
                Err(e) => {
                    // Deterministic derivation means this is a serious custodian or
                    // node bug; the original material is kept.
                    error!(target: "seismic::rotation", %e, epoch, "custodian served conflicting keys for an epoch")
                }
            },
            Err(e) => {
                // The announcement delay bought time; keep retrying until activation.
                // If activation arrives first, block execution stalls on
                // MissingEpochKeys and resumes when a later fetch succeeds.
                warn!(target: "seismic::rotation", %e, epoch, "failed to fetch purpose keys for announced epoch; will retry")
            }
        }
    }

    let unfetched = keyring.unfetched_scheduled_epochs().len();
    metrics::gauge!("seismic.rotation.pending_unfetched_epochs").set(unfetched as f64);
    if unfetched > 0 {
        if let Some((epoch, activation_block)) = keyring.pending() {
            error!(
                target: "seismic::rotation",
                epoch,
                activation_block,
                known_tip = keyring.known_tip(),
                "purpose keys for a pending rotation are not fetched yet; the node will stall at activation without them"
            );
        }
    }
}

/// Reads the full rotation schedule from the registry's storage at the latest state.
/// An absent account or empty length slot yields an empty schedule (the dormant
/// pre-contract path).
fn read_registry_schedule<Client>(client: &Client) -> eyre::Result<RotationSchedule>
where
    Client: StateProviderFactory,
{
    let state = client.latest()?;
    // Registry slots are ordinary public storage; the privacy flag is ignored.
    let len = state.storage(KEY_ROTATION_REGISTRY, ROTATIONS_LEN_SLOT)?.unwrap_or_default().value;
    let len = u64::try_from(len).map_err(|_| eyre::eyre!("rotations length overflows u64"))?;
    if len > MAX_ROTATIONS {
        return Err(eyre::eyre!("rotations length {len} exceeds the {MAX_ROTATIONS} cap"));
    }

    let mut entries = Vec::with_capacity(len as usize);
    for index in 0..len {
        let word = state
            .storage(KEY_ROTATION_REGISTRY, rotation_entry_slot(index))?
            .unwrap_or_default()
            .value;
        entries.push(decode_rotation_entry(B256::from(word), index)?);
    }
    Ok(RotationSchedule::from_entries(entries)?)
}

/// Merges a freshly read schedule into the keyring, logging any divergence loudly
/// instead of adopting it (the registry is append-only; divergence is a bug or a
/// deeper-than-`MIN_ACTIVATION_DELAY` reorg).
fn apply_schedule_updates(keyring: &PurposeKeyring, schedule: &RotationSchedule) {
    if schedule.len() <= keyring.schedule_len() {
        return;
    }
    match keyring.apply_schedule(schedule) {
        Ok(new_rotations) if new_rotations > 0 => {
            info!(target: "seismic::rotation", new_rotations, total = schedule.len(), "learned new key-rotation announcements");
        }
        Ok(_) => {}
        Err(e) => {
            error!(target: "seismic::rotation", %e, "rotation registry history diverged; refusing to adopt it");
        }
    }
}

/// Whether the committed chain segment emitted a `RotationAnnounced` log from the
/// registry. A hint only — reconciliation always goes back to storage.
fn has_rotation_announcement(notification: &CanonStateNotification<SeismicPrimitives>) -> bool {
    let chain = notification.committed();
    let announced = chain.blocks_and_receipts().any(|(_, receipts)| {
        receipts.iter().any(|receipt| {
            receipt.logs().iter().any(|log| {
                log.address == KEY_ROTATION_REGISTRY &&
                    log.topics().first() == Some(&*ROTATION_ANNOUNCED_TOPIC)
            })
        })
    });
    announced
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_provider::test_utils::MockEthProvider;

    /// With no registry contract deployed (the state of every network today), the
    /// schedule reads as empty and reconciliation is a no-op.
    #[test]
    fn absent_registry_reads_as_empty_schedule() {
        let provider = MockEthProvider::<SeismicPrimitives>::new();
        let schedule = read_registry_schedule(&provider).unwrap_or_else(|e| {
            panic!("reading an absent registry must succeed with an empty schedule: {e}")
        });
        assert!(schedule.is_empty());
    }
}
