//! End-to-end regression test for the block-import chain-ID bypass (audit finding).
//!
//! Txpool admission rejects a transaction whose embedded chain ID differs from the
//! configured chain. A block received through Summit consensus and imported via
//! `engine_newPayload` does not pass through the local txpool, so the same invariant
//! has to be enforced at the execution boundary. This test drives the real engine
//! `newPayload` handler with a block a Byzantine proposer could craft — one that
//! carries a wrong-chain transaction — and asserts the node rejects it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test file - panics are acceptable

use alloy_consensus::proofs::calculate_transaction_root;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, Bytes, TxKind};
use alloy_rpc_types_engine::PayloadStatusEnum;
use eyre::Result;
use reth_payload_primitives::PayloadTypes;
use reth_primitives_traits::SealedBlock;
use reth_seismic_node::{
    engine::SeismicPayloadTypes,
    utils::e2e::{ensure_mock_purpose_keys, setup},
};
use reth_seismic_primitives::{SeismicBlock, SeismicTransactionSigned};
use reth_seismic_test_utils::{get_unsigned_legacy_tx_request, sign_tx};
use std::time::Duration;

/// A block containing a transaction signed for a different chain must be rejected by
/// `engine_newPayload`, mirroring the txpool's chain-ID admission check.
#[tokio::test(flavor = "multi_thread")]
async fn test_new_payload_rejects_wrong_chain_id_tx() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await?;
    let mut node = nodes.pop().unwrap();

    // Build — but do NOT submit — an empty payload on top of genesis. This yields a
    // fully valid block skeleton (base fee, timestamp, blob/withdrawals/requests fields,
    // and the empty-execution state root) so the crafted block clears every
    // pre-execution consensus check and actually reaches transaction execution.
    let empty = node.new_payload().await?;

    // A legacy transaction signed for a *different* chain, from a genesis-funded account
    // at nonce 0. The local txpool would reject this outright; a Byzantine proposer
    // bypasses the pool by placing it directly into a payload.
    let wrong_chain_id = wallet.chain_id + 1;
    let req = get_unsigned_legacy_tx_request(
        &wallet.inner,
        0,
        TxKind::Call(Address::random()),
        wrong_chain_id,
        Bytes::new(),
    )
    .await;
    let envelope = sign_tx(wallet.inner.clone(), req).await;
    let raw = envelope.encoded_2718();
    let wrong_tx = SeismicTransactionSigned::decode_2718(&mut raw.as_slice())?;

    // Insert the wrong-chain tx into the empty block's body and re-seal so the
    // transactions root and block hash stay internally consistent. The state root is
    // deliberately left as the empty-block root: with the fix, execution fails on the
    // chain-ID check before the state root is ever compared.
    let mut block: SeismicBlock = empty.block().clone().into_block();
    block.body.transactions.push(wrong_tx);
    block.header.transactions_root = calculate_transaction_root(&block.body.transactions);
    let sealed = SealedBlock::seal_slow(block);

    // Submit through the engine's newPayload handler (the ConfigureEngineEvm import path).
    //
    // This is Seismic-owned test code, not an upstream helper edit. The invalid payload should
    // return quickly; until our fork absorbs upstream reth#23837's e2e payload-helper fix, keep
    // intentional waits in this regression bounded so CI reports the stuck rejection path instead
    // of timing out the entire integration-test job.
    let status = tokio::time::timeout(
        Duration::from_secs(15),
        node.inner
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(SeismicPayloadTypes::block_to_payload(sealed)),
    )
    .await
    .expect("engine_newPayload timed out rejecting wrong-chain transaction")?;

    assert!(
        status.is_invalid(),
        "engine_newPayload must reject a block with a wrong-chain transaction, got: {status:?}"
    );
    match status.status {
        PayloadStatusEnum::Invalid { validation_error } => {
            assert!(
                validation_error.to_lowercase().contains("chain"),
                "expected a chain-ID validation error, got: {validation_error}"
            );
        }
        other => panic!("expected INVALID payload status, got: {other:?}"),
    }

    Ok(())
}
