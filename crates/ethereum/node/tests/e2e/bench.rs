use crate::utils::eth_payload_attributes;
use alloy_primitives::{address, hex, Bytes, TxKind};
use eyre::Ok;
use reth::rpc::compat::block;
use reth_chainspec::{ChainSpecBuilder, DEV, MAINNET};
use reth_e2e_test_utils::{setup, transaction::{legacy_tx, seismic_tx, SeismicTransactionTestContext}};
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::*;
use std::{sync::Arc, time::Instant};

#[tokio::test(flavor = "multi_thread")]
async fn print_tx() -> eyre::Result<()> {
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

    let input = Bytes::from_static(&hex!("60806040525f5f8190b150610285806100175f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806324a7f0b71461004357806343bd0d701461005f578063d09de08a1461007d575b5f5ffd5b61005d600480360381019061005891906100f6565b610087565b005b610067610090565b604051610074919061013b565b60405180910390f35b6100856100a7565b005b805f8190b15050565b5f600160025fb06100a19190610181565b14905090565b5f5f81b0809291906100b8906101de565b919050b150565b5f5ffd5b5f819050919050565b6100d5816100c3565b81146100df575f5ffd5b50565b5f813590506100f0816100cc565b92915050565b5f6020828403121561010b5761010a6100bf565b5b5f610118848285016100e2565b91505092915050565b5f8115159050919050565b61013581610121565b82525050565b5f60208201905061014e5f83018461012c565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61018b826100c3565b9150610196836100c3565b9250826101a6576101a5610154565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101e8826100c3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361021a576102196101b1565b5b60018201905091905056fea2646970667358221220ea421d58b6748a9089335034d76eb2f01bceafe3dfac2e57d9d2e766852904df64736f6c63782c302e382e32382d646576656c6f702e323032342e31322e392b636f6d6d69742e39383863313261662e6d6f64005d"));
    let nonce = 0;
    let tx = seismic_tx(&wallet.inner, DEV.chain.id(), input, nonce, TxKind::Create);
    let tx_signed = SeismicTransactionTestContext::sign_tx(&wallet.inner, tx).await;
    let raw_tx = tx_signed.envelope_encoded();
    println!("raw_tx: {:?}", raw_tx);

    let input = Bytes::from_static(&hex!("43bd0d70"));
    let nonce = 1;
    let contract_addr = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
    let tx = seismic_tx(&wallet.inner, DEV.chain.id(), input, nonce, TxKind::Call(contract_addr));
    let tx_signed = SeismicTransactionTestContext::sign_tx(&wallet.inner, tx).await;
    let raw_tx = tx_signed.envelope_encoded();
    println!("raw_tx: {:?}", raw_tx);

    let input = Bytes::from_static(&hex!("24a7f0b70000000000000000000000000000000000000000000000000000000000000003"));
    let nonce = 1;
    let contract_addr = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
    let tx = seismic_tx(&wallet.inner, DEV.chain.id(), input, nonce, TxKind::Call(contract_addr));
    let tx_signed = SeismicTransactionTestContext::sign_tx(&wallet.inner, tx).await;
    let raw_tx = tx_signed.envelope_encoded();
    println!("raw_tx: {:?}", raw_tx);

    let input = Bytes::from_static(&hex!("43bd0d70"));
    let nonce = 2;
    let contract_addr = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
    let tx = seismic_tx(&wallet.inner, DEV.chain.id(), input, nonce, TxKind::Call(contract_addr));
    let tx_signed = SeismicTransactionTestContext::sign_tx(&wallet.inner, tx).await;
    let raw_tx = tx_signed.envelope_encoded();
    println!("raw_tx: {:?}", raw_tx);

    Ok(())
}

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

    // ==================== second block for benching seismic transactions ====================
    let tx_receipt = second_node.rpc.get_transaction_receipt(tx_hash).await?.unwrap();

    let deployed_contract_address = tx_receipt.contract_address.unwrap();
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

        let _ = first_node.rpc.call(raw_tx, block_number).await?;
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
        let _ = first_node.rpc.call(raw_tx, block_number).await?;
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