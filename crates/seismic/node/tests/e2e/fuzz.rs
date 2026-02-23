//! E2E fuzz tests: send adversarial transactions to a live node and verify it stays up.
//!
//! Starts a dev node once, sends batches of malformed/adversarial transactions
//! across all tx types (hardcoded edge cases + random payloads), and health-checks
//! the node after each batch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types::{Block, TransactionInput, TransactionRequest};
use core::str::FromStr;
use jsonrpsee::{core::client::ClientT, rpc_params};
use rand::Rng;
use reth_e2e_test_utils::wallet::Wallet;
use reth_seismic_node::utils::test_utils::{
    get_nonce, get_signed_seismic_tx_bytes, SeismicRethTestCommand,
};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use std::{thread, time::Duration};
use tokio::sync::mpsc;

const WAIT: u64 = 1;
/// Number of random payloads per fuzz batch
const RANDOM_CASES: usize = 50;

async fn get_recent_block_hash(client: &jsonrpsee::http_client::HttpClient) -> B256 {
    let result: serde_json::Value = client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .expect("Failed to get latest block");
    let hash_str = result["hash"].as_str().expect("Block hash not found");
    B256::from_str(hash_str).expect("Failed to parse block hash")
}

async fn assert_node_alive(client: &jsonrpsee::http_client::HttpClient, wallet_addr: Address) {
    let _ = get_nonce(client, wallet_addr).await;
}

async fn send_raw(
    client: &jsonrpsee::http_client::HttpClient,
    raw: Bytes,
    label: &str,
) {
    let result = EthApiOverrideClient::<Block>::send_raw_transaction(client, raw.into()).await;
    match result {
        Err(_) => println!("[OK] {label}: rejected"),
        Ok(hash) => println!("[ACCEPTED] {label}: {hash:?}"),
    }
}

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
        to: Some(TxKind::Call(Address::ZERO)),
        value: Some(U256::ZERO),
        input: TransactionInput::default(),
        ..Default::default()
    };

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
    let mut rng = rand::thread_rng();

    // =========================================================================
    // Batch A: Hardcoded malformed raw bytes
    // =========================================================================
    println!("\n=== Batch A: Hardcoded malformed raw bytes ===");

    send_raw(&client, Bytes::new(), "empty bytes").await;
    send_raw(&client, Bytes::from(vec![0x03]), "0x03 (EIP-4844 prefix)").await;
    send_raw(&client, Bytes::from(vec![0x4A]), "0x4A (Seismic prefix)").await;
    send_raw(&client, Bytes::from(vec![0xFF; 1024]), "1KB of 0xFF").await;
    send_raw(&client, Bytes::from(vec![0x02, 0xF8, 0x50, 0x01]), "truncated EIP-1559 RLP").await;
    send_raw(&client, Bytes::from(vec![0x03, 0xF8, 0x50, 0x01, 0x02, 0x03]), "truncated EIP-4844 RLP").await;
    send_raw(&client, Bytes::from(vec![0x4A, 0xF8, 0x50, 0x01]), "truncated Seismic RLP").await;
    send_raw(&client, Bytes::from((0u8..=255).collect::<Vec<u8>>()), "256 sequential bytes").await;

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch A");

    // =========================================================================
    // Batch B: Random raw bytes (fuzzed)
    // =========================================================================
    println!("\n=== Batch B: {RANDOM_CASES} random raw byte payloads ===");

    // All valid EIP-2718 type prefixes plus some invalid ones
    let type_prefixes: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x4A, 0x7F, 0x80, 0xFE, 0xFF];

    for i in 0..RANDOM_CASES {
        let len = rng.gen_range(1..4096);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        // 50% of the time, use a real type prefix to exercise the decoder further
        if rng.gen_bool(0.5) {
            bytes[0] = type_prefixes[rng.gen_range(0..type_prefixes.len())];
        }
        send_raw(&client, Bytes::from(bytes), &format!("random#{i}")).await;
    }

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch B");

    // =========================================================================
    // Batch C: Hardcoded adversarial standard txs
    // =========================================================================
    println!("\n=== Batch C: Hardcoded adversarial standard txs ===");

    let nonce = get_nonce(&client, addr).await;

    let cases: Vec<(&str, TransactionRequest)> = vec![
        ("gas_limit=0", TransactionRequest { gas: Some(0), ..Default::default() }),
        ("priority_fee > max_fee", TransactionRequest {
            max_fee_per_gas: Some(1_000),
            max_priority_fee_per_gas: Some(1_000_000),
            ..Default::default()
        }),
        ("value > balance", TransactionRequest {
            value: Some(U256::from(10u128.pow(30))),
            ..Default::default()
        }),
        ("128KB input", TransactionRequest {
            gas: Some(30_000_000),
            input: TransactionInput { input: Some(Bytes::from(vec![0xDE; 128_000])), data: None },
            ..Default::default()
        }),
    ];

    for (label, overrides) in cases {
        let raw = build_signed_1559(&eth_wallet, nonce, chain_id, overrides).await;
        send_raw(&client, raw, &format!("EIP-1559 {label}")).await;
    }

    let raw = build_signed_1559(&eth_wallet, u64::MAX, chain_id, Default::default()).await;
    send_raw(&client, raw, "EIP-1559 nonce=u64::MAX").await;

    let raw = build_signed_1559(&eth_wallet, nonce, 999999, Default::default()).await;
    send_raw(&client, raw, "EIP-1559 wrong chain_id").await;

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch C");

    // =========================================================================
    // Batch D: Random adversarial EIP-1559 txs (fuzzed fields)
    // =========================================================================
    println!("\n=== Batch D: {RANDOM_CASES} random adversarial EIP-1559 txs ===");

    for i in 0..RANDOM_CASES {
        let overrides = TransactionRequest {
            gas: Some(rng.gen_range(0..30_000_000)),
            max_fee_per_gas: Some(rng.gen_range(0..u128::from(u64::MAX))),
            max_priority_fee_per_gas: Some(rng.gen_range(0..u128::from(u64::MAX))),
            value: Some(U256::from(rng.gen::<u128>())),
            input: TransactionInput {
                input: Some(Bytes::from(
                    (0..rng.gen_range(0..1024)).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>()
                )),
                data: None,
            },
            ..Default::default()
        };
        let raw = build_signed_1559(&eth_wallet, rng.gen(), chain_id, overrides).await;
        send_raw(&client, raw, &format!("random-1559#{i}")).await;
    }

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch D");

    // =========================================================================
    // Batch E: Hardcoded adversarial seismic txs
    // =========================================================================
    println!("\n=== Batch E: Hardcoded adversarial seismic txs ===");

    let recent_block_hash = get_recent_block_hash(&client).await;

    let seismic_cases: Vec<(&str, TxKind, Bytes, B256)> = vec![
        ("garbage calldata", TxKind::Call(Address::ZERO), Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]), recent_block_hash),
        ("zero block hash", TxKind::Call(Address::ZERO), Bytes::from(vec![0x01]), B256::ZERO),
        ("random block hash", TxKind::Call(Address::ZERO), Bytes::from(vec![0x01]), B256::from([0xFF; 32])),
        ("create tx", TxKind::Create, Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xF3]), recent_block_hash),
        ("empty calldata", TxKind::Call(Address::ZERO), Bytes::new(), recent_block_hash),
        ("64KB calldata", TxKind::Call(Address::ZERO), Bytes::from(vec![0xAB; 64_000]), recent_block_hash),
    ];

    for (label, to, calldata, block_hash) in seismic_cases {
        let raw = get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(&client, addr).await,
            to,
            chain_id,
            calldata,
            block_hash,
        ).await;
        send_raw(&client, raw, &format!("seismic {label}")).await;
    }

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch E");

    // =========================================================================
    // Batch F: Random adversarial seismic txs (fuzzed fields)
    // =========================================================================
    println!("\n=== Batch F: {RANDOM_CASES} random adversarial seismic txs ===");

    for i in 0..RANDOM_CASES {
        let calldata_len = rng.gen_range(0..4096);
        let calldata = Bytes::from((0..calldata_len).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>());

        // Randomly pick: valid block hash, zero, or random
        let block_hash = match rng.gen_range(0..3) {
            0 => recent_block_hash,
            1 => B256::ZERO,
            _ => B256::from(rng.gen::<[u8; 32]>()),
        };

        let to = if rng.gen_bool(0.2) {
            TxKind::Create
        } else {
            TxKind::Call(Address::from(rng.gen::<[u8; 20]>()))
        };

        let raw = get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(&client, addr).await,
            to,
            chain_id,
            calldata,
            block_hash,
        ).await;
        send_raw(&client, raw, &format!("random-seismic#{i}")).await;
    }

    assert_node_alive(&client, addr).await;
    println!("Node alive after batch F");

    // =========================================================================
    // Final health check
    // =========================================================================
    println!("\n=== Final health check ===");
    assert_node_alive(&client, addr).await;
    println!("Node alive after all batches — test passed");
    println!("Total payloads sent: {}", 8 + RANDOM_CASES + 6 + RANDOM_CASES + 6 + RANDOM_CASES);

    shutdown_tx.try_send(()).unwrap();
    thread::sleep(Duration::from_secs(WAIT));
}
