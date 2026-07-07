//! End-to-end verification for the signed-read block-import policy (audit claim).
//!
//! A signed-read seismic transaction is an RPC `eth_call` construct that must never
//! execute as a state transition. The txpool/RPC gate rejects it on admission, but a
//! block imported via `engine_newPayload` bypasses the txpool. This test drives the
//! real engine `newPayload` handler with a block carrying a signed-read transaction —
//! the shape a Byzantine proposer could craft — and asserts the node rejects it.
//!
//! The gate lives in the consensus-type decoder (`SeismicTransactionSigned::typed_decode`),
//! which the payload→block conversion in `SeismicEngineValidator::ensure_well_formed_payload`
//! runs on every payload transaction, so a signed-read tx fails to decode at import.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test file - panics are acceptable

use alloy_consensus::proofs::calculate_transaction_root;
use alloy_primitives::{aliases::U96, Address, Bytes, Signature, TxKind, B256, U256};
use eyre::Result;
use reth_payload_primitives::PayloadTypes;
use reth_primitives_traits::SealedBlock;
use reth_seismic_node::{
    engine::SeismicPayloadTypes,
    utils::e2e::{ensure_mock_purpose_keys, setup},
};
use reth_seismic_primitives::{SeismicBlock, SeismicTransactionSigned};
use secp256k1::PublicKey;
use seismic_alloy_consensus::{SeismicTypedTransaction, TxSeismic, TxSeismicElements};
use std::str::FromStr;

/// A `signed_read = true` seismic transaction. The signature is arbitrary: the consensus
/// decoder gates on `signed_read` before any signature recovery, so a dummy signature
/// exercises exactly the path we care about.
fn signed_read_tx(chain_id: u64) -> SeismicTransactionSigned {
    let tx = TxSeismic {
        chain_id,
        nonce: 0,
        gas_price: 1,
        gas_limit: 21_000,
        to: TxKind::Call(Address::with_last_byte(1)),
        value: U256::ZERO,
        input: Bytes::new(),
        seismic_elements: TxSeismicElements {
            encryption_pubkey: PublicKey::from_str(
                "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
            )
            .unwrap(),
            encryption_nonce: U96::ZERO,
            message_version: 2,
            recent_block_hash: B256::ZERO,
            expires_at_block: 1,
            signed_read: true,
        },
        authorization_list: vec![],
    };
    let signature = Signature::new(U256::from(1u64), U256::from(1u64), false);
    SeismicTransactionSigned::new_unhashed(SeismicTypedTransaction::Seismic(tx), signature)
}

/// A block containing a signed-read seismic transaction must be rejected by
/// `engine_newPayload`, mirroring the txpool's signed-read admission policy.
#[tokio::test(flavor = "multi_thread")]
async fn test_new_payload_rejects_signed_read_tx() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await?;
    let mut node = nodes.pop().unwrap();

    // Build — but do NOT submit — an empty payload on top of genesis to obtain a valid
    // block skeleton, then splice in the signed-read transaction and re-seal so the
    // transactions root and block hash stay internally consistent.
    let empty = node.new_payload().await?;
    let mut block: SeismicBlock = empty.block().clone().into_block();
    block.body.transactions.push(signed_read_tx(wallet.chain_id));
    block.header.transactions_root = calculate_transaction_root(&block.body.transactions);
    let sealed = SealedBlock::seal_slow(block);

    // Submit through the engine's newPayload handler. The signed-read tx must fail the
    // consensus-decode gate, so the payload is rejected rather than executed.
    let result = node
        .inner
        .add_ons_handle
        .beacon_engine_handle
        .new_payload(SeismicPayloadTypes::block_to_payload(sealed))
        .await;

    match result {
        Ok(status) => {
            assert!(
                status.is_invalid(),
                "engine_newPayload must reject a block with a signed-read transaction, got: {status:?}"
            );
            assert!(
                format!("{status:?}").to_lowercase().contains("signed-read"),
                "expected a signed-read rejection, got: {status:?}"
            );
        }
        Err(e) => {
            assert!(
                format!("{e:?}").to_lowercase().contains("signed-read"),
                "expected a signed-read rejection, got err: {e:?}"
            );
        }
    }

    Ok(())
}
