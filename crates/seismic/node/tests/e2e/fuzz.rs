//! E2E fuzz tests: send adversarial transactions to a live node and verify it stays up.
//!
//! Starts a dev node once, sends batches of malformed/adversarial transactions
//! across all tx types, and health-checks the node after each batch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Bytes, TxKind, B256, U256};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use core::str::FromStr;
use jsonrpsee::{core::client::ClientT, rpc_params};
use reth_e2e_test_utils::wallet::Wallet;
use reth_seismic_node::utils::test_utils::{
    get_nonce, get_signed_seismic_tx_bytes, SeismicRethTestCommand,
};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use alloy_rpc_types::Block;
use std::{thread, time::Duration};
use tokio::sync::mpsc;

const WAIT: u64 = 1;

async fn get_recent_block_hash(client: &jsonrpsee::http_client::HttpClient) -> B256 {
    let result: serde_json::Value = client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .expect("Failed to get latest block");
    let hash_str = result["hash"].as_str().expect("Block hash not found");
    B256::from_str(hash_str).expect("Failed to parse block hash")
}

/// Health check: if this fails, the node crashed
async fn assert_node_alive(client: &jsonrpsee::http_client::HttpClient, wallet_addr: alloy_primitives::Address) {
    let result = get_nonce(client, wallet_addr).await;
    // get_nonce succeeds = node is responding to RPC
    let _ = result;
}

/// Send raw bytes via `eth_sendRawTransaction` and expect an error (not a crash).
async fn send_raw_expect_error(
    client: &jsonrpsee::http_client::HttpClient,
    raw: Bytes,
    label: &str,
) {
    let result = EthApiOverrideClient::<Block>::send_raw_transaction(client, raw.into()).await;
    match result {
        Err(_) => println!("[OK] {label}: rejected with error"),
        Ok(hash) => println!("[ACCEPTED] {label}: tx_hash={hash:?} (may revert at execution)"),
    }
}

/// Build and sign a standard EIP-1559 tx with the given fields.
async fn build_signed_1559(
    wallet: &EthereumWallet,
    nonce: u64,
    chain_id: u64,
    overrides: TransactionRequest,
) -> Bytes {
    let mut tx = TransactionRequest {
        nonce: Some(nonce),
        chain_id: Some(chain_id),
        gas: Some(21_000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(1e9 as u128),
        to: Some(TxKind::Call(alloy_primitives::Address::ZERO)),
        value: Some(U256::ZERO),
        input: TransactionInput::default(),
        ..Default::default()
    };

    // Apply overrides
    if overrides.gas.is_some() { tx.gas = overrides.gas; }
    if overrides.max_fee_per_gas.is_some() { tx.max_fee_per_gas = overrides.max_fee_per_gas; }
    if overrides.max_priority_fee_per_gas.is_some() { tx.max_priority_fee_per_gas = overrides.max_priority_fee_per_gas; }
    if overrides.to.is_some() { tx.to = overrides.to; }
    if overrides.value.is_some() { tx.value = overrides.value; }
    if overrides.input.input.is_some() { tx.input = overrides.input; }

    let envelope = tx.build(wallet).await.expect("Failed to build tx");
    TxEnvelope::encoded_2718(&envelope).into()
}

#[tokio::test(flavor = "multi_thread")]
async fn fuzz_adversarial_transactions() {
    // Start the node
    let (tx, mut rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    SeismicRethTestCommand::run(tx, shutdown_rx).await;
    rx.recv().await.unwrap();

    let rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
    let client = jsonrpsee::http_client::HttpClientBuilder::default().build(rpc_url).unwrap();
    let wallet = Wallet::default().with_chain_id(chain_id);
    let eth_wallet: EthereumWallet = wallet.inner.clone().into();
    let addr = wallet.inner.address();

    // =========================================================================
    // Batch A: Malformed raw bytes
    // =========================================================================
    println!("\n=== Batch A: Malformed raw bytes ===");

    send_raw_expect_error(&client, Bytes::new(), "empty bytes").await;
    send_raw_expect_error(&client, Bytes::from(vec![0x03]), "single byte 0x03 (EIP-4844 prefix)").await;
    send_raw_expect_error(&client, Bytes::from(vec![0x4A]), "single byte 0x4A (Seismic prefix)").await;
    send_raw_expect_error(&client, Bytes::from(vec![0xFF; 1024]), "1KB of 0xFF").await;
    send_raw_expect_error(&client, Bytes::from(vec![0x02, 0xF8, 0x50, 0x01]), "truncated EIP-1559 RLP").await;
    send_raw_expect_error(&client, Bytes::from(vec![0x03, 0xF8, 0x50, 0x01, 0x02, 0x03]), "truncated EIP-4844 RLP").await;
    send_raw_expect_error(&client, Bytes::from(vec![0x4A, 0xF8, 0x50, 0x01]), "truncated Seismic RLP").await;
    // Random bytes that happen to start with valid type prefixes
    send_raw_expect_error(
        &client,
        Bytes::from((0u8..=255).collect::<Vec<u8>>()),
        "256 sequential bytes",
    ).await;

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch A");

    // =========================================================================
    // Batch B: Standard tx types with adversarial fields
    // =========================================================================
    println!("\n=== Batch B: Adversarial standard txs ===");

    let nonce = get_nonce(&client, addr).await;

    // Legacy/EIP-1559 with gas_limit = 0
    let raw = build_signed_1559(&eth_wallet, nonce, chain_id, TransactionRequest {
        gas: Some(0),
        ..Default::default()
    }).await;
    send_raw_expect_error(&client, raw, "EIP-1559 gas_limit=0").await;

    // EIP-1559 with max_priority_fee > max_fee_per_gas
    let raw = build_signed_1559(&eth_wallet, nonce, chain_id, TransactionRequest {
        max_fee_per_gas: Some(1_000),
        max_priority_fee_per_gas: Some(1_000_000),
        ..Default::default()
    }).await;
    send_raw_expect_error(&client, raw, "EIP-1559 priority_fee > max_fee").await;

    // EIP-1559 with value > balance (overspend)
    let raw = build_signed_1559(&eth_wallet, nonce, chain_id, TransactionRequest {
        value: Some(U256::from(10u128.pow(30))), // way more than funded
        ..Default::default()
    }).await;
    send_raw_expect_error(&client, raw, "EIP-1559 value > balance").await;

    // EIP-1559 with huge input data
    let raw = build_signed_1559(&eth_wallet, nonce, chain_id, TransactionRequest {
        gas: Some(30_000_000),
        input: TransactionInput { input: Some(Bytes::from(vec![0xDE; 128_000])), data: None },
        ..Default::default()
    }).await;
    send_raw_expect_error(&client, raw, "EIP-1559 128KB input").await;

    // EIP-1559 with nonce far in the future
    let raw = build_signed_1559(&eth_wallet, u64::MAX, chain_id, Default::default()).await;
    send_raw_expect_error(&client, raw, "EIP-1559 nonce=u64::MAX").await;

    // EIP-1559 with wrong chain_id
    let raw = build_signed_1559(&eth_wallet, nonce, 999999, Default::default()).await;
    send_raw_expect_error(&client, raw, "EIP-1559 wrong chain_id").await;

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch B");

    // =========================================================================
    // Batch C: Seismic tx types with adversarial fields
    // =========================================================================
    println!("\n=== Batch C: Adversarial seismic txs ===");

    let recent_block_hash = get_recent_block_hash(&client).await;

    // Seismic tx with random calldata (not valid encrypted data)
    let result = get_signed_seismic_tx_bytes(
        &wallet.inner,
        get_nonce(&client, addr).await,
        TxKind::Call(alloy_primitives::Address::ZERO),
        chain_id,
        Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        recent_block_hash,
    ).await;
    send_raw_expect_error(&client, result, "seismic tx with garbage calldata").await;

    // Seismic tx with `recent_block_hash = B256::ZERO`
    let result = get_signed_seismic_tx_bytes(
        &wallet.inner,
        get_nonce(&client, addr).await,
        TxKind::Call(alloy_primitives::Address::ZERO),
        chain_id,
        Bytes::from(vec![0x01]),
        B256::ZERO, // not in recent 100 blocks
    ).await;
    send_raw_expect_error(&client, result, "seismic tx with zero block hash").await;

    // Seismic tx with random block hash
    let result = get_signed_seismic_tx_bytes(
        &wallet.inner,
        get_nonce(&client, addr).await,
        TxKind::Call(alloy_primitives::Address::ZERO),
        chain_id,
        Bytes::from(vec![0x01]),
        B256::from([0xFF; 32]), // random, definitely not recent
    ).await;
    send_raw_expect_error(&client, result, "seismic tx with random block hash").await;

    // Seismic tx to Create (contract deployment with seismic type)
    let result = get_signed_seismic_tx_bytes(
        &wallet.inner,
        get_nonce(&client, addr).await,
        TxKind::Create,
        chain_id,
        Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xF3]), // minimal bytecode
        recent_block_hash,
    ).await;
    send_raw_expect_error(&client, result, "seismic tx to Create").await;

    // Seismic tx with empty calldata
    let result = get_signed_seismic_tx_bytes(
        &wallet.inner,
        get_nonce(&client, addr).await,
        TxKind::Call(alloy_primitives::Address::ZERO),
        chain_id,
        Bytes::new(),
        recent_block_hash,
    ).await;
    send_raw_expect_error(&client, result, "seismic tx with empty calldata").await;

    // Seismic tx with very large calldata
    let result = get_signed_seismic_tx_bytes(
        &wallet.inner,
        get_nonce(&client, addr).await,
        TxKind::Call(alloy_primitives::Address::ZERO),
        chain_id,
        Bytes::from(vec![0xAB; 64_000]),
        recent_block_hash,
    ).await;
    send_raw_expect_error(&client, result, "seismic tx with 64KB calldata").await;

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch C");

    // =========================================================================
    // Final: Confirm node is still responsive after all adversarial batches
    // =========================================================================
    println!("\n=== Final health check ===");

    assert_node_alive(&client, addr).await;
    println!("Node alive after all adversarial batches — test passed");

    // Shutdown
    shutdown_tx.try_send(()).unwrap();
    thread::sleep(Duration::from_secs(WAIT));
}
