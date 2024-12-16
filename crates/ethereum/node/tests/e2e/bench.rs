use crate::utils::eth_payload_attributes;
use alloy_primitives::{hex, Bytes, TxKind};
use eyre::Ok;
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_e2e_test_utils::{setup, transaction::SeismicTransactionTestContext};
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::*;
use std::{sync::Arc, time::Instant};


#[tokio::test(flavor = "multi_thread")]
async fn bench() -> eyre::Result<()> {
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
    let send_raw_tx_cnt = 1399;
    let call_cnt = send_raw_tx_cnt * 1;

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

    let tx_receipt = second_node.rpc.get_transaction_receipt(tx_hash).await?.unwrap();

    let deployed_contract_address = tx_receipt.contract_address.unwrap();

    // ==================== second block for benching seismic transactions ====================
    let data: Bytes = vec![].into();
    let mut tx_hashes = vec![];

    let start_time = Instant::now();

    // run calls
    for _ in 0..call_cnt {
        let raw_tx = SeismicTransactionTestContext::call_seismic_tx_bytes(
            MAINNET.chain.id(),
            wallet.inner.clone(),
            nonce,
            deployed_contract_address,
            data.clone(),
        )
        .await;

        let _ = first_node.rpc.signed_call(raw_tx, block_number).await?;
    }

    let call_end_time = Instant::now();

    // run raw transactions
    for _ in 0..send_raw_tx_cnt {
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
        tx_hashes.push(tx_hash);
    }

    // make the node advance
    let start_time_inner = Instant::now();
    let (payload, _) = first_node.advance_block(vec![], eth_payload_attributes).await?;
    let end_time_inner = Instant::now();

    let block_hash = payload.block().hash();
    block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    first_node.assert_new_block(tx_hashes[0], block_hash, block_number).await?;

    // only send forkchoice update to second node
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;

    // expect second node advanced via p2p gossip
    second_node.assert_new_block(tx_hashes[0], block_hash, 2).await?;

    let end_time = Instant::now();
    let duration = end_time.duration_since(start_time);
    let duration_call = call_end_time.duration_since(start_time);
    let duration_advance_block = end_time_inner.duration_since(start_time_inner);
    debug!(
        target: "e2e:bench",
        ?duration,
        "Duration for encrypted transaction in a block with {} calls and {} raw transactions",
        call_cnt,
        send_raw_tx_cnt
    );
    debug!(
        target: "e2e:bench",
        ?duration_call,
        "Duration for calls with {} calls and {} raw transactions",
        call_cnt,
        send_raw_tx_cnt
    );
    debug!(
        target: "e2e:bench",
        ?duration_advance_block,
        "Duration for encrypted transaction in a block with {} calls and {} raw transactions",
        call_cnt,
        send_raw_tx_cnt
    );
    debug!(target: "e2e:bench", ?nonce, "after the first block");
    debug!(target: "e2e:bench", ?block_number, "after the first block");

    // ==================== third block for benching normal transactions ====================
    let start_time = Instant::now();
    let mut tx_hashes = vec![];

    // run calls
    for _ in 0..call_cnt {
        let raw_tx = SeismicTransactionTestContext::call_legacy_tx_bytes(
            MAINNET.chain.id(),
            wallet.inner.clone(),
            nonce,
            deployed_contract_address,
            data.clone(),
        )
        .await;
        let _ = first_node.rpc.signed_call(raw_tx, block_number).await?;
    }

    // run transactions
    for _ in 0..send_raw_tx_cnt {
        let raw_tx = SeismicTransactionTestContext::call_legacy_tx_bytes(
            MAINNET.chain.id(),
            wallet.inner.clone(),
            nonce,
            deployed_contract_address,
            data.clone(),
        )
        .await;
        nonce += 1;

        let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;
        tx_hashes.push(tx_hash);
    }
    let call_end_time = Instant::now();

    // make the node advance
    let start_time_inner = Instant::now();
    let (payload, _) = first_node.advance_block(vec![], eth_payload_attributes).await?;
    let end_time_inner = Instant::now();

    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    first_node.assert_new_block(tx_hashes[0], block_hash, block_number).await?;

    // only send forkchoice update to second node
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;

    // expect second node advanced via p3p gossip
    second_node.assert_new_block(tx_hashes[0], block_hash, block_number).await?;

    let end_time = Instant::now();
    let duration = end_time.duration_since(start_time);
    let duration_call = call_end_time.duration_since(start_time);
    let duration_inner = end_time_inner.duration_since(start_time_inner);
    debug!(
        target: "e2e:bench",
        ?duration,
        "Duration for normal transaction in a block with {} calls and {} raw transactions",
        call_cnt,
        send_raw_tx_cnt
    );
    debug!(
        target: "e2e:bench",
        ?duration_call,
        "Duration of calls for normal transaction in a block with {} calls and {} raw transactions",
        call_cnt,
        send_raw_tx_cnt
    );

    debug!(
        target: "e2e:bench",
        ?duration_inner,
        "Duration of block production for normal transaction in a block with {} calls and {} raw transactions",
        call_cnt,
        send_raw_tx_cnt
    );
    Ok(())
}
