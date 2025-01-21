use alloy_primitives::{bytes::Buf, hex, Address, Bytes, TxKind, U256};
use reth_chainspec::DEV;
use reth_e2e_test_utils::setup;
use reth_node_builder::engine_tree_config::DEFAULT_BACKUP_THRESHOLD;
use reth_tracing::tracing::*;
use seismic_node::{
    node::SeismicNode,
    utils::{seismic_payload_attributes, test_utils::get_signed_seismic_tx_bytes},
};
use std::{sync::Arc, time::Instant};

#[tokio::test(flavor = "multi_thread")]
async fn backup() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let chain_id = DEV.chain;
    let (mut nodes, _tasks, wallet) =
        setup::<SeismicNode>(2, DEV.clone(), false, seismic_payload_attributes).await?;

    let mut second_node = nodes.pop().unwrap();
    let mut first_node = nodes.pop().unwrap();
    let mut nonce = 0;
    let mut block_number;

    // ==================== first block for encrypted transaction ====================
    let raw_tx =
        get_signed_seismic_tx_bytes(&wallet.inner, nonce, TxKind::Create, chain_id.id(), input.clone()).await;

    nonce += 1;

    // Make the nodes advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;
    let (payload, _) = first_node.advance_block().await?;
    let block_hash = payload.block().hash();
    block_number = payload.block().number;
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;
    second_node.assert_new_block(tx_hash, block_hash, 1).await?;

    let tx_receipt = second_node.rpc.transaction_receipt(tx_hash).await?.unwrap();

    let deployed_contract_address = tx_receipt.contract_address.unwrap();
    let data: Bytes = vec![].into();

    // run raw transactions
    for _ in 0..DEFAULT_BACKUP_THRESHOLD + 1 {
        let raw_tx = get_signed_seismic_tx_bytes(
            &wallet.inner,
            nonce,
            alloy_primitives::TxKind::Call(deployed_contract_address),
            chain_id.id(),
            input.clone(),
        )
        .await;
        nonce += 1;

        let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;

        let (payload, _) = first_node.advance_block().await?;

        let block_hash = payload.block().hash();
        block_number = payload.block().number;

        // assert the block has been committed to the blockchain
        first_node.assert_new_block(tx_hash, block_hash, block_number).await?;

        // only send forkchoice update to second node
        second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;

        // expect second node advanced via p2p gossip
        second_node.assert_new_block(tx_hash, block_hash, block_number).await?;

        debug!(
            target: "e2e:backup",
            ?block_number,
        );
    }

    let backup_dir = first_node.inner.data_dir.backup();
    let backup_size = std::fs::read_dir(&backup_dir)?
        .map(|entry| entry.map(|e| e.metadata().map(|m| m.len()).unwrap_or(0)).unwrap_or(0))
        .sum::<u64>();

    info!(
        target: "e2e:bench",
        "Backup directory size: {} bytes",
        backup_size,
    );
    Ok(())
}
