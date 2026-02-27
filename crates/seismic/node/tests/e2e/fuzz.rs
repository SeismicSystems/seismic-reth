//! E2E fuzz tests for adversarial transaction handling.
//!
//! Spins up a dev node and bombards it with malformed, adversarial, and
//! signature-corrupted transactions across all tx types. Verifies the node
//! stays healthy after each batch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types::{Block, TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use core::str::FromStr;
use futures::FutureExt;
use jsonrpsee::{core::client::ClientT, rpc_params};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use reth_e2e_test_utils::wallet::Wallet;
use reth_seismic_node::utils::test_utils::{
    get_nonce, get_signed_seismic_tx_bytes, SeismicRethTestCommand,
};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, trace};

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
    get_nonce(client, wallet_addr).await;
}

/// Sends raw bytes to the node. Logs the outcome at trace level so accidental
/// acceptances are visible in CI logs when run with `--nocapture` or `RUST_LOG=trace`.
async fn send_raw(client: &jsonrpsee::http_client::HttpClient, raw: Bytes) {
    match EthApiOverrideClient::<Block>::send_raw_transaction(client, raw.into()).await {
        Ok(hash) => trace!(?hash, "tx accepted"),
        Err(e) => trace!(%e, "tx rejected"),
    }
}

/// Sends raw bytes and asserts the node rejects them. Use for deterministic
/// hardcoded cases where acceptance would indicate a validation bug.
async fn assert_rejected(client: &jsonrpsee::http_client::HttpClient, raw: Bytes) {
    assert!(
        EthApiOverrideClient::<Block>::send_raw_transaction(client, raw.into()).await.is_err(),
        "expected rejection for known-invalid payload"
    );
}

/// Builds a signed EIP-1559 transaction with sensible defaults, then applies
/// field-level overrides so callers can target individual validation paths.
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
        max_fee_per_gas: Some(20_000_000_000u128),
        max_priority_fee_per_gas: Some(1_000_000_000u128),
        to: Some(TxKind::Call(Address::ZERO)),
        value: Some(U256::ZERO),
        input: TransactionInput::default(),
        ..Default::default()
    };

    if overrides.gas.is_some() {
        tx.gas = overrides.gas;
    }
    if overrides.max_fee_per_gas.is_some() {
        tx.max_fee_per_gas = overrides.max_fee_per_gas;
    }
    if overrides.max_priority_fee_per_gas.is_some() {
        tx.max_priority_fee_per_gas = overrides.max_priority_fee_per_gas;
    }
    if overrides.to.is_some() {
        tx.to = overrides.to;
    }
    if overrides.value.is_some() {
        tx.value = overrides.value;
    }
    if overrides.input.input.is_some() {
        tx.input = overrides.input;
    }

    let envelope = tx.build(wallet).await.expect("Failed to build tx");
    TxEnvelope::encoded_2718(&envelope).into()
}

/// Replaces the last `n` bytes of `src` using a per-byte transform.
fn corrupt_last_n(src: &[u8], n: usize, f: impl Fn(u8) -> u8) -> Bytes {
    let mut buf = src.to_vec();
    for b in buf.iter_mut().rev().take(n) {
        *b = f(*b);
    }
    Bytes::from(buf)
}

/// Replaces the last `n` bytes of `src` with random values.
fn corrupt_tail_random(src: &[u8], n: usize, rng: &mut impl Rng) -> Bytes {
    let mut buf = src.to_vec();
    for b in buf.iter_mut().rev().take(n) {
        *b = rng.random();
    }
    Bytes::from(buf)
}

// Sends hardcoded and randomly-generated malformed raw byte payloads.
// Exercises the RLP decoder and EIP-2718 type-prefix handling.
async fn send_malformed_raw_bytes(
    client: &jsonrpsee::http_client::HttpClient,
    addr: Address,
    rng: &mut SmallRng,
) {
    // empty payload
    assert_rejected(client, Bytes::new()).await;
    // bare EIP-4844 type prefix
    assert_rejected(client, Bytes::from(vec![0x03])).await;
    // bare seismic type prefix
    assert_rejected(client, Bytes::from(vec![0x4A])).await;
    // 1 KB of 0xFF
    assert_rejected(client, Bytes::from(vec![0xFF; 1024])).await;
    // truncated EIP-1559 RLP
    assert_rejected(client, Bytes::from(vec![0x02, 0xF8, 0x50, 0x01])).await;
    // truncated EIP-4844 RLP
    assert_rejected(client, Bytes::from(vec![0x03, 0xF8, 0x50, 0x01, 0x02, 0x03])).await;
    // truncated seismic RLP
    assert_rejected(client, Bytes::from(vec![0x4A, 0xF8, 0x50, 0x01])).await;
    // 256 sequential bytes (0x00..0xFF)
    assert_rejected(client, Bytes::from((0u8..=255).collect::<Vec<u8>>())).await;

    let type_prefixes: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x4A, 0x7F, 0x80, 0xFE, 0xFF];

    for _ in 0..RANDOM_CASES {
        let len = rng.random_range(1..4096);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        // 50% chance of using a real type prefix
        if rng.random_bool(0.5) {
            bytes[0] = type_prefixes[rng.random_range(0..type_prefixes.len())];
        }
        send_raw(client, Bytes::from(bytes)).await;
    }

    assert_node_alive(client, addr).await;
    info!("Node alive after malformed raw bytes (8 hardcoded + {RANDOM_CASES} random)");
}

// Sends hardcoded and randomly-generated adversarial EIP-1559 transactions.
// Tests validation of gas limits, fee parameters, value, and nonce bounds.
async fn send_adversarial_eip1559_txs(
    client: &jsonrpsee::http_client::HttpClient,
    eth_wallet: &EthereumWallet,
    addr: Address,
    chain_id: u64,
    rng: &mut SmallRng,
) {
    let nonce = get_nonce(client, addr).await;

    // gas_limit = 0
    assert_rejected(
        client,
        build_signed_1559(
            eth_wallet,
            nonce,
            chain_id,
            TransactionRequest { gas: Some(0), ..Default::default() },
        )
        .await,
    )
    .await;

    // priority_fee > max_fee
    assert_rejected(
        client,
        build_signed_1559(
            eth_wallet,
            nonce,
            chain_id,
            TransactionRequest {
                max_fee_per_gas: Some(1_000),
                max_priority_fee_per_gas: Some(1_000_000),
                ..Default::default()
            },
        )
        .await,
    )
    .await;

    // value exceeds balance
    assert_rejected(
        client,
        build_signed_1559(
            eth_wallet,
            nonce,
            chain_id,
            TransactionRequest { value: Some(U256::from(10u128.pow(30))), ..Default::default() },
        )
        .await,
    )
    .await;

    // 128 KB input data (use u64::MAX nonce to ensure rejection — with valid gas
    // and chain_id this would otherwise be a valid mempool tx)
    assert_rejected(
        client,
        build_signed_1559(
            eth_wallet,
            u64::MAX,
            chain_id,
            TransactionRequest {
                gas: Some(30_000_000),
                input: TransactionInput {
                    input: Some(Bytes::from(vec![0xDE; 128_000])),
                    data: None,
                },
                ..Default::default()
            },
        )
        .await,
    )
    .await;

    // nonce = u64::MAX
    assert_rejected(
        client,
        build_signed_1559(eth_wallet, u64::MAX, chain_id, Default::default()).await,
    )
    .await;

    // wrong chain_id
    assert_rejected(client, build_signed_1559(eth_wallet, nonce, 999999, Default::default()).await)
        .await;

    for _ in 0..RANDOM_CASES {
        let overrides = TransactionRequest {
            gas: Some(rng.random_range(0..30_000_000)),
            max_fee_per_gas: Some(rng.random_range(0..u128::from(u64::MAX))),
            max_priority_fee_per_gas: Some(rng.random_range(0..u128::from(u64::MAX))),
            value: Some(U256::from(rng.random::<u128>())),
            input: TransactionInput {
                input: Some(Bytes::from(
                    (0..rng.random_range(0..1024)).map(|_| rng.random::<u8>()).collect::<Vec<u8>>(),
                )),
                data: None,
            },
            ..Default::default()
        };
        send_raw(client, build_signed_1559(eth_wallet, rng.random(), chain_id, overrides).await)
            .await;
    }

    assert_node_alive(client, addr).await;
    info!("Node alive after adversarial EIP-1559 txs (6 hardcoded + {RANDOM_CASES} random)");
}

// Sends hardcoded and randomly-generated adversarial seismic transactions.
// Tests encryption metadata, block-hash validation, and calldata handling.
//
// TODO: add cases that corrupt seismic-specific fields (encryption_pubkey,
// encryption_nonce) post-encoding, similar to the signature corruption approach.
async fn send_adversarial_seismic_txs(
    client: &jsonrpsee::http_client::HttpClient,
    signer: &PrivateKeySigner,
    addr: Address,
    chain_id: u64,
    rng: &mut SmallRng,
) {
    let nonce = get_nonce(client, addr).await;
    let recent_block_hash = get_recent_block_hash(client).await;

    // zero block hash
    assert_rejected(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Call(Address::ZERO),
            chain_id,
            Bytes::from(vec![0x01]),
            B256::ZERO,
        )
        .await,
    )
    .await;

    // random block hash
    assert_rejected(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Call(Address::ZERO),
            chain_id,
            Bytes::from(vec![0x01]),
            B256::from([0xFF; 32]),
        )
        .await,
    )
    .await;

    // nonce = u64::MAX
    assert_rejected(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            u64::MAX,
            TxKind::Call(Address::ZERO),
            chain_id,
            Bytes::from(vec![0x01]),
            recent_block_hash,
        )
        .await,
    )
    .await;

    // wrong chain_id
    assert_rejected(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Call(Address::ZERO),
            999999,
            Bytes::from(vec![0x01]),
            recent_block_hash,
        )
        .await,
    )
    .await;

    // garbage calldata
    send_raw(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Call(Address::ZERO),
            chain_id,
            Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            recent_block_hash,
        )
        .await,
    )
    .await;

    // contract creation
    send_raw(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Create,
            chain_id,
            Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xF3]),
            recent_block_hash,
        )
        .await,
    )
    .await;

    // empty calldata
    send_raw(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Call(Address::ZERO),
            chain_id,
            Bytes::new(),
            recent_block_hash,
        )
        .await,
    )
    .await;

    // 64 KB calldata
    send_raw(
        client,
        get_signed_seismic_tx_bytes(
            signer,
            nonce,
            TxKind::Call(Address::ZERO),
            chain_id,
            Bytes::from(vec![0xAB; 64_000]),
            recent_block_hash,
        )
        .await,
    )
    .await;

    for _ in 0..RANDOM_CASES {
        let calldata_len = rng.random_range(0..4096);
        let calldata =
            Bytes::from((0..calldata_len).map(|_| rng.random::<u8>()).collect::<Vec<u8>>());

        let block_hash = match rng.random_range(0..3) {
            0 => recent_block_hash,
            1 => B256::ZERO,
            _ => B256::from(rng.random::<[u8; 32]>()),
        };

        let to = if rng.random_bool(0.2) {
            TxKind::Create
        } else {
            TxKind::Call(Address::from(rng.random::<[u8; 20]>()))
        };

        send_raw(
            client,
            get_signed_seismic_tx_bytes(signer, rng.random(), to, chain_id, calldata, block_hash)
                .await,
        )
        .await;
    }

    assert_node_alive(client, addr).await;
    info!("Node alive after adversarial seismic txs (8 hardcoded + {RANDOM_CASES} random)");
}

// Builds valid signed transactions, then corrupts parts of their signatures.
// Tests ecrecover / signer-recovery resilience for both EIP-1559 and seismic txs.
async fn send_signature_corrupted_txs(
    client: &jsonrpsee::http_client::HttpClient,
    eth_wallet: &EthereumWallet,
    signer: &PrivateKeySigner,
    addr: Address,
    chain_id: u64,
    rng: &mut SmallRng,
) {
    let nonce = get_nonce(client, addr).await;
    let recent_block_hash = get_recent_block_hash(client).await;

    let valid_bytes =
        build_signed_1559(eth_wallet, nonce, chain_id, Default::default()).await.to_vec();

    // corrupt last byte (part of signature s value)
    send_raw(client, corrupt_last_n(&valid_bytes, 1, |b| b ^ 0xFF)).await;
    // randomize entire s value
    send_raw(client, corrupt_tail_random(&valid_bytes, 32, rng)).await;
    // randomize entire r + s
    send_raw(client, corrupt_tail_random(&valid_bytes, 64, rng)).await;
    // zero out the entire signature
    send_raw(client, corrupt_last_n(&valid_bytes, 65, |_| 0x00)).await;
    // all-0xFF signature
    send_raw(client, corrupt_last_n(&valid_bytes, 65, |_| 0xFF)).await;

    let seismic_bytes = get_signed_seismic_tx_bytes(
        signer,
        nonce,
        TxKind::Call(Address::ZERO),
        chain_id,
        Bytes::from(vec![0x01]),
        recent_block_hash,
    )
    .await
    .to_vec();

    // corrupt last byte of seismic tx signature
    send_raw(client, corrupt_last_n(&seismic_bytes, 1, |b| b ^ 0xFF)).await;
    // randomize seismic r + s
    send_raw(client, corrupt_tail_random(&seismic_bytes, 64, rng)).await;

    // random single-byte signature corruption across many txs
    for _ in 0..RANDOM_CASES {
        let raw = build_signed_1559(eth_wallet, rng.random(), chain_id, Default::default()).await;
        let mut bytes = raw.to_vec();
        let len = bytes.len();
        let offset = rng.random_range(len.saturating_sub(65)..len);
        bytes[offset] = rng.random();
        send_raw(client, Bytes::from(bytes)).await;
    }

    assert_node_alive(client, addr).await;
    info!("Node alive after signature-corrupted txs (7 hardcoded + {RANDOM_CASES} random)");
}

#[tokio::test(flavor = "multi_thread")]
async fn fuzz_adversarial_transactions() {
    reth_tracing::init_test_tracing();

    let (tx, mut rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    SeismicRethTestCommand::run(tx, shutdown_rx).await;

    // Wrap the entire test body (including startup wait) in catch_unwind so
    // that shutdown_tx is always sent — even if the node never becomes ready
    // or a batch panics — preventing leaked child processes and port conflicts.
    let result = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(120), rx.recv())
            .await
            .expect("Timed out waiting for node to become ready")
            .expect("Node readiness channel closed");

        let seed: u64 = std::env::var("FUZZ_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(rand::random);
        info!(%seed, "RNG seed — re-run with FUZZ_SEED={seed} to reproduce");
        let mut rng = SmallRng::seed_from_u64(seed);

        let rpc_url = SeismicRethTestCommand::url();
        let chain_id = SeismicRethTestCommand::chain_id();
        let client = jsonrpsee::http_client::HttpClientBuilder::default().build(rpc_url).unwrap();
        let wallet = Wallet::default().with_chain_id(chain_id);
        let eth_wallet: EthereumWallet = wallet.inner.clone().into();
        let addr = wallet.inner.address();

        send_malformed_raw_bytes(&client, addr, &mut rng).await;
        send_adversarial_eip1559_txs(&client, &eth_wallet, addr, chain_id, &mut rng).await;
        send_adversarial_seismic_txs(&client, &wallet.inner, addr, chain_id, &mut rng).await;
        send_signature_corrupted_txs(&client, &eth_wallet, &wallet.inner, addr, chain_id, &mut rng)
            .await;
    })
    .catch_unwind()
    .await;

    let _ = shutdown_tx.try_send(());
    tokio::time::sleep(Duration::from_secs(WAIT)).await;

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }

    info!("All batches passed — node remained healthy throughout");
}
