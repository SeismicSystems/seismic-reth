use crate::utils::eth_payload_attributes;
use alloy_primitives::{Bytes, TxHash};
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_e2e_test_utils::{
    setup,
    transaction::{SeismicTransactionTestContext, TransactionTestContext},
};
use reth_node_ethereum::EthereumNode;
use tokio::{runtime::Runtime, task};
use std::{io::Read, sync::Arc, time::Instant};

#[tokio::test]
async fn can_sync() -> eyre::Result<()> {
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

    // ==================== first block with regular transfer transaction ========
    let raw_tx =
        TransactionTestContext::transfer_tx_bytes(MAINNET.chain.id(), wallet.inner.clone()).await;

    // Make the first node advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;

    // make the node advance
    let (payload, _) = first_node.advance_block(vec![], eth_payload_attributes).await?;

    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;

    // only send forkchoice update to second node
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;

    // expect second node advanced via p2p gossip
    second_node.assert_new_block(tx_hash, block_hash, 1).await?;

    // ==================== second block for encrypted transaction ====================
    let raw_tx =
        SeismicTransactionTestContext::deploy_tx_bytes(MAINNET.chain.id(), wallet.inner.clone(), 1)
            .await;

    // Make the first node advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;

    // make the node advance
    let (payload, _) = first_node.advance_block(vec![], eth_payload_attributes).await?;

    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;

    // only send forkchoice update to second node
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;

    // expect second node advanced via p2p gossip
    second_node.assert_new_block(tx_hash, block_hash, 2).await?;

    // ========= testing call =================
    let tx_receipt = second_node.rpc.get_transaction_receipt(tx_hash).await?.unwrap();

    let deployed_contract_address = tx_receipt.contract_address.unwrap();
    let data: Bytes = vec![3u8; 32].into();

    let raw_tx = SeismicTransactionTestContext::call_tx_bytes(
        MAINNET.chain.id(),
        wallet.inner.clone(),
        2,
        deployed_contract_address,
        data.clone(),
    )
    .await;

    let output = first_node.rpc.call(raw_tx, 2).await?;

    Ok(())
}
