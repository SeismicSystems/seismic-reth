use crate::utils::eth_payload_attributes;
use alloy_primitives::Bytes;
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_e2e_test_utils::{setup, transaction::SeismicTransactionTestContext};
use reth_node_ethereum::EthereumNode;
use reth_primitives_traits::constants::BACKUP_SLOTS;
use reth_tracing::tracing::*;
use std::{sync::Arc, time::Instant};

#[tokio::test(flavor = "multi_thread")]
async fn backup() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut nodes, _tasks, wallet) = setup::<EthereumNode>(
        2,
        Arc::new(
            ChainSpecBuilder::default()
                .chain(MAINNET.chain)
                .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
                .cancun_activated()
                .build(),
        ),
        false,
    )
    .await?;

    let mut second_node = nodes.pop().unwrap();
    let mut first_node = nodes.pop().unwrap();
    let mut nonce = 0;
    let mut block_number;

    // ==================== first block for encrypted transaction ====================
    let raw_tx = SeismicTransactionTestContext::deploy_tx_bytes(
        MAINNET.chain.id(),
        wallet.inner.clone(),
        nonce,
    )
    .await;
    nonce += 1;

    // Make the first node advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;

    // make the node advance
    let (payload, _) = first_node.advance_block(vec![], eth_payload_attributes).await?;

    let block_hash = payload.block().hash();
    block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;

    // only send forkchoice update to second node
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;

    // expect second node advanced via p2p gossip
    second_node.assert_new_block(tx_hash, block_hash, 1).await?;

    // ==================== second block for benching seismic transactions ====================
    let tx_receipt = second_node.rpc.get_transaction_receipt(tx_hash).await?.unwrap();

    let deployed_contract_address = tx_receipt.contract_address.unwrap();
    let data: Bytes = vec![].into();

    // run raw transactions
    for _ in 0..BACKUP_SLOTS {
        let raw_tx = SeismicTransactionTestContext::call_seismic_tx_bytes(
            MAINNET.chain.id(),
            wallet.inner.clone(),
            nonce,
            deployed_contract_address,
            data.clone(),
        )
        .await;
        nonce += 1;

        let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;

        let (payload, _) = first_node.advance_block(vec![], eth_payload_attributes).await?;

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
