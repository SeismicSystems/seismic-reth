//! Engine API reorg plus the real canonical rotation watcher.
//!
//! Kept in a separate integration-test binary because the e2e node helpers use a
//! process-global purpose keyring. This fixture must not share fetched epochs with
//! the simulation tests, which deliberately require an unfetched epoch.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Bytes, TxKind, B256};
use alloy_sol_types::{sol, SolCall};
use reth_chainspec::make_genesis_header;
use reth_e2e_test_utils::{setup_engine, wallet::Wallet};
use reth_node_core::args::{PurposeKeysArgs, PurposeKeysSource};
use reth_primitives_traits::SealedHeader;
use reth_provider::CanonStateSubscriptions;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_keys::{
    registry::{ADMIN_SLOT, KEY_ROTATION_REGISTRY},
    PurposeKeyring,
};
use reth_seismic_node::{
    node::SeismicNode,
    rotation::watch_key_rotations,
    utils::e2e::{ensure_mock_purpose_keys, seismic_payload_attributes},
};
use reth_seismic_test_utils::{get_unsigned_legacy_tx_request, sign_tx};
use std::{sync::Arc, time::Duration};

sol! {
    function announceRotation(uint64 activationBlock);
}

async fn wait_for_view(keyring: &PurposeKeyring, hash: B256) -> eyre::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while keyring.canonical_view().head_hash != hash {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_reorg_removes_orphaned_announcement_but_retains_keys() -> eyre::Result<()> {
    tokio::time::timeout(Duration::from_secs(90), engine_reorg()).await?
}

async fn engine_reorg() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();
    let mut spec = SEISMIC_DEV.as_ref().clone();
    spec.genesis
        .alloc
        .get_mut(&KEY_ROTATION_REGISTRY)
        .unwrap()
        .storage
        .as_mut()
        .unwrap()
        .insert(ADMIN_SLOT, Wallet::default().inner.address().into_word());
    spec.genesis_header =
        SealedHeader::seal_slow(make_genesis_header(&spec.genesis, &spec.hardforks));
    let (mut nodes, tasks, wallet) = tokio::spawn(setup_engine::<SeismicNode>(
        1,
        Arc::new(spec),
        false,
        Default::default(),
        seismic_payload_attributes,
    ))
    .await??;
    let mut node = nodes.pop().unwrap();
    let keyring = node.inner.evm_config.executor_factory.keyring.clone();
    let args = PurposeKeysArgs { source: PurposeKeysSource::BuiltIn, ..Default::default() };
    tasks.executor().spawn_critical(
        "rotation-reorg-regression",
        watch_key_rotations(
            node.inner.provider.clone(),
            keyring.clone(),
            args,
            node.inner.provider.canonical_state_stream(),
        ),
    );
    wait_for_view(&keyring, node.block_hash(0)).await?;

    // Build the empty competing child before the node has seen any announcement.
    // Both children are built on genesis; neither is finalized.
    let replacement = node.new_payload().await?;
    let request = get_unsigned_legacy_tx_request(
        &wallet.inner,
        0,
        TxKind::Call(KEY_ROTATION_REGISTRY),
        wallet.chain_id,
        Bytes::from(announceRotationCall { activationBlock: 33 }.abi_encode()),
    )
    .await;
    let signed = sign_tx(wallet.inner.clone(), request).await;
    node.rpc.inject_tx(signed.encoded_2718().into()).await?;
    let orphan = node.new_payload().await?;
    assert_ne!(orphan.block().hash(), replacement.block().hash());
    node.submit_payload(orphan.clone()).await?;
    node.update_optimistic_forkchoice(orphan.block().hash()).await?;
    wait_for_view(&keyring, orphan.block().hash()).await?;
    assert_eq!(keyring.pending(), Some((1, 33)));
    tokio::time::timeout(Duration::from_secs(10), async {
        while keyring.keys_for_epoch(1).is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;

    // Validate the prebuilt competing payload after orphan exposure, then make
    // it canonical. The watcher must replace (not extend) the registry view.
    node.submit_payload(replacement.clone()).await?;
    node.update_optimistic_forkchoice(replacement.block().hash()).await?;
    wait_for_view(&keyring, replacement.block().hash()).await?;
    assert_eq!(keyring.known_tip(), 1);
    assert_eq!(keyring.pending(), None);
    assert_eq!(keyring.epoch_for_block(33), 0);
    assert!(keyring.keys_for_epoch(1).is_some(), "historical material must not be evicted");
    Ok(())
}
