//! E2E tests for ops whitelist/revoke via sentinel transactions in `eth_sendRawTransaction`.

use alloy_consensus::SignableTransaction;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, aliases::U96, Address, Bytes, TxKind, B256, U256};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use reth_chainspec::{make_genesis_header, Chain, ChainSpec};
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_builder::{EngineNodeLauncher, Node, NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::{DevArgs, RpcServerArgs};
use reth_primitives_traits::SealedHeader;
use reth_rpc_builder::RpcModuleSelection;
use reth_rpc_layer::{eip712_signing_hash, WHITELIST_TX_SENTINEL};
use reth_seismic_node::{
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, SEISMIC_TIMESTAMP_MULTIPLIER},
};
use reth_tasks::TaskManager;
use seismic_alloy_consensus::{TxSeismic, TxSeismicElements, TypedDataRequest};
use std::{str::FromStr, sync::Arc};

sol! {
    interface OpsWhitelistTxAuth {
        function whitelistKey(
            address target,
            uint64 keyExpiresAtBlock,
            bytes32 recentBlockHash,
            uint64 expiresAtBlock,
            bytes32 validatorId,
            uint64 nonce
        ) external;
        function revokeKey(
            address target,
            bytes32 recentBlockHash,
            uint64 expiresAtBlock,
            bytes32 validatorId,
            uint64 nonce
        ) external;
    }
}

/// Far-future block used for "valid for the rest of the test" whitelist entries.
/// The test chain only produces a few blocks per test, so any large number works.
const FAR_FUTURE_BLOCK: u64 = 1_000_000_000;

/// The Params contract address.
const PARAMS_CONTRACT: Address = address!("0x0000000000000000000000000000506172616d73");

/// Build a Seismic dev chain spec with a custom governance address in the Params contract.
fn dev_chain_spec_with_governance(governance_address: Address) -> Arc<ChainSpec> {
    let mut genesis: alloy_genesis::Genesis =
        serde_json::from_str(include_str!("../../../chainspec/res/genesis/dev.json"))
            .expect("deserialize dev genesis");

    #[cfg(not(feature = "timestamp-in-seconds"))]
    {
        genesis.timestamp *= 1000;
    }

    // Overwrite slot 0 of the Params contract with the governance address.
    let mut value = [0u8; 32];
    value[12..].copy_from_slice(governance_address.as_slice());
    if let Some(account) = genesis.alloc.get_mut(&PARAMS_CONTRACT) {
        if let Some(ref mut storage) = account.storage {
            storage.insert(alloy_primitives::B256::ZERO, alloy_primitives::B256::from(value));
        }
    }

    let hardforks = reth_seismic_forks::SEISMIC_DEV_HARDFORKS.clone();
    Arc::new(ChainSpec {
        chain: Chain::from_id(5124),
        genesis_header: SealedHeader::seal_slow(make_genesis_header(&genesis, &hardforks)),
        genesis,
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks,
        ..Default::default()
    })
}

fn seismic_payload_attributes(timestamp: u64) -> reth_payload_builder::EthPayloadBuilderAttributes {
    use alloy_primitives::B256;
    use alloy_rpc_types_engine::PayloadAttributes;
    reth_payload_builder::EthPayloadBuilderAttributes::new(
        B256::ZERO,
        PayloadAttributes {
            timestamp: timestamp * SEISMIC_TIMESTAMP_MULTIPLIER,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: Address::ZERO,
            withdrawals: Some(vec![]),
            parent_beacon_block_root: Some(B256::ZERO),
        },
    )
}

/// Build and sign a legacy transaction targeting the sentinel address with the given calldata.
fn build_sentinel_tx(signer: &PrivateKeySigner, chain_id: u64, calldata: Bytes) -> Bytes {
    let tx = alloy_consensus::TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_limit: 100_000,
        gas_price: 0,
        to: TxKind::Call(WHITELIST_TX_SENTINEL),
        value: U256::ZERO,
        input: calldata,
    };

    let sig = signer.sign_hash_sync(&tx.signature_hash()).expect("sign sentinel tx");
    let signed = tx.into_signed(sig);
    let envelope = alloy_consensus::TxEnvelope::Legacy(signed);
    Encodable2718::encoded_2718(&envelope).into()
}

/// Send `eth_sendRawTransaction` and return either the tx hash on success or the error string.
async fn submit_sentinel(client: &HttpClient, raw_tx: &Bytes) -> Result<String, String> {
    let hex = format!("0x{}", alloy_primitives::hex::encode(raw_tx));
    match client.request::<serde_json::Value, _>("eth_sendRawTransaction", rpc_params![hex]).await {
        Ok(v) => Ok(v.as_str().expect("tx hash string").to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Build and sign a sentinel transaction in its EIP-712 typed-data form, returning
/// the wire request plus the tx hash the node is expected to report back.
///
/// `eth_sendRawTransaction` accepts two payload forms: raw RLP bytes and EIP-712
/// typed data. The typed-data form can only express a `TxSeismic` (type 0x4A) —
/// `SeismicTxEnvelope::decode_712` decodes nothing else — so unlike
/// [`build_sentinel_tx`] (a legacy tx) the sentinel call here rides in a seismic tx
/// with `message_version = 2`, which selects the EIP-712 signing hash that the node
/// recovers the signer against after re-encoding the typed data to RLP. The
/// whitelist calldata is carried as plaintext `input`: sentinel txs are intercepted
/// at the RPC layer, which parses `input` directly and never decrypts, so the
/// encryption-related seismic elements are inert plumbing here.
fn build_sentinel_typed_data_tx(
    signer: &PrivateKeySigner,
    chain_id: u64,
    calldata: Bytes,
    env: Envelope,
) -> (TypedDataRequest, B256) {
    let tx = TxSeismic {
        chain_id,
        nonce: 0,
        gas_price: 0,
        gas_limit: 100_000,
        to: TxKind::Call(WHITELIST_TX_SENTINEL),
        value: U256::ZERO,
        input: calldata,
        seismic_elements: TxSeismicElements {
            // Any well-formed compressed secp256k1 point works — nothing on the
            // sentinel path performs ECDH against it.
            encryption_pubkey: secp256k1::PublicKey::from_str(
                "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
            )
            .expect("valid compressed secp256k1 point"),
            encryption_nonce: U96::ZERO,
            message_version: 2,
            recent_block_hash: env.recent_block_hash,
            expires_at_block: env.expires_at_block,
            signed_read: false,
        },
        authorization_list: vec![],
    };
    let sig = signer.sign_hash_sync(&tx.signature_hash()).expect("sign typed-data sentinel tx");
    let signed = tx.into_signed(sig);
    let expected_hash = *signed.hash();
    (signed.into(), expected_hash)
}

/// Send `eth_sendRawTransaction` with the EIP-712 typed-data payload form
/// (`SeismicRawTxRequest::TypedData`; with `serde(untagged)` it goes over the wire
/// as a `{"data": <EIP-712 typed data>, "signature": <sig>}` object instead of a
/// hex string). Returns either the tx hash on success or the error string.
async fn submit_sentinel_typed_data(
    client: &HttpClient,
    typed: &TypedDataRequest,
) -> Result<String, String> {
    match client.request::<serde_json::Value, _>("eth_sendRawTransaction", rpc_params![typed]).await
    {
        Ok(v) => Ok(v.as_str().expect("tx hash string").to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Per-tx replay-protection envelope plumbed into both calldata variants.
#[derive(Clone, Copy)]
struct Envelope {
    recent_block_hash: B256,
    expires_at_block: u64,
    validator_id: B256,
    nonce: u64,
}

fn whitelist_calldata(target: Address, key_expires_at_block: u64, env: Envelope) -> Bytes {
    OpsWhitelistTxAuth::whitelistKeyCall {
        target,
        keyExpiresAtBlock: key_expires_at_block,
        recentBlockHash: env.recent_block_hash,
        expiresAtBlock: env.expires_at_block,
        validatorId: env.validator_id,
        nonce: env.nonce,
    }
    .abi_encode()
    .into()
}

fn revoke_calldata(target: Address, env: Envelope) -> Bytes {
    OpsWhitelistTxAuth::revokeKeyCall {
        target,
        recentBlockHash: env.recent_block_hash,
        expiresAtBlock: env.expires_at_block,
        validatorId: env.validator_id,
        nonce: env.nonce,
    }
    .abi_encode()
    .into()
}

/// Returns (hash, number) of the current canonical head via eth RPC.
async fn latest_block(client: &HttpClient) -> (B256, u64) {
    let block: serde_json::Value = client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .expect("eth_getBlockByNumber latest");
    let hash: B256 = block["hash"].as_str().expect("block hash").parse().expect("parse hash");
    let number = u64::from_str_radix(
        block["number"].as_str().expect("block number").trim_start_matches("0x"),
        16,
    )
    .expect("parse block number");
    (hash, number)
}

/// Read `validator_id` from the unauthenticated bootstrap endpoint on the ops server.
async fn ops_get_validator_id(ops_client: &HttpClient) -> B256 {
    ops_client.request("ops_getValidatorId", rpc_params![]).await.expect("ops_getValidatorId")
}

/// Read `admin_nonce` from the unauthenticated bootstrap endpoint on the ops server.
async fn ops_get_admin_nonce(ops_client: &HttpClient) -> u64 {
    ops_client.request("ops_getAdminNonce", rpc_params![]).await.expect("ops_getAdminNonce")
}

/// Build an ops jsonrpsee client; bootstrap reads need no signature.
fn build_ops_client(ops_url: &str) -> HttpClient {
    HttpClientBuilder::default().build(ops_url).expect("ops http client")
}

/// Send a signed request to the ops RPC server.
async fn send_ops_signed_request(
    url: &str,
    body: &str,
    signer: &PrivateKeySigner,
    nonce: Option<&str>,
    chain_id: u64,
) -> reqwest::Response {
    let signing_nonce = nonce.unwrap_or("");
    let hash = eip712_signing_hash(body.as_bytes(), signing_nonce, chain_id);
    let signature = signer.sign_hash(&hash).await.unwrap();
    let sig_hex = alloy_primitives::hex::encode(signature.as_bytes());

    let mut req = reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Signature", &sig_hex);
    if let Some(nonce) = nonce {
        req = req.header("X-Nonce", nonce);
    }
    req.body(body.to_string()).send().await.unwrap()
}

fn ops_get_storage_request(address: Address, slot: alloy_primitives::B256, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_getStorageAt",
        "params": [format!("{address:?}"), format!("{slot:?}"), "latest"],
        "id": id
    })
    .to_string()
}

/// Launch a Seismic node with ops enabled and a custom governance address.
async fn launch_ops_node(
    governance_signer: &PrivateKeySigner,
) -> eyre::Result<(
    reth_e2e_test_utils::NodeHelperType<
        SeismicNode,
        reth_provider::providers::BlockchainProvider<
            reth_node_api::NodeTypesWithDBAdapter<SeismicNode, reth_e2e_test_utils::TmpDB>,
        >,
    >,
    TaskManager,
    Wallet,
)> {
    let chain_spec = dev_chain_spec_with_governance(governance_signer.address());
    let tasks = TaskManager::current();
    let exec = tasks.executor();

    ensure_mock_purpose_keys();

    let mut rpc_args = RpcServerArgs::default()
        .with_unused_ports()
        .with_http()
        .with_http_api(RpcModuleSelection::All);
    rpc_args.ops_enable = true;
    // Use a random unused port.
    rpc_args.ops_port = 0;
    // Disable since not needed. Furthermore default endpoint is a global
    // `/tmp/reth.ipc-*` socket that some test environments forbid creating,
    // such as inside sandboxed llm harness.
    rpc_args.ipcdisable = true;

    let node_config = NodeConfig::new(chain_spec)
        .with_unused_ports()
        .with_dev(DevArgs { dev: true, ..Default::default() })
        .with_rpc(rpc_args);

    let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
        .testing_node(exec)
        .with_types_and_provider::<SeismicNode, reth_provider::providers::BlockchainProvider<_>>()
        .with_components(SeismicNode::default().components_builder())
        .with_add_ons(SeismicNode::default().add_ons())
        .launch_with_fn(|builder| {
            let launcher = EngineNodeLauncher::new(
                builder.task_executor().clone(),
                builder.config().datadir(),
                Default::default(),
            );
            builder.launch_with(launcher)
        })
        .await?;

    let node =
        reth_e2e_test_utils::node::NodeTestContext::new(node, seismic_payload_attributes).await?;
    let wallet = Wallet::default().with_chain_id(5124);

    Ok((node, tasks, wallet))
}

/// Resolve the ops server URL from a launched node. Macro because the underlying
/// `NodeTestContext` is heavily trait-bound and a generic fn would require
/// repeating those bounds at every call site.
macro_rules! node_ops_url {
    ($node:expr) => {
        format!(
            "http://{}",
            $node
                .inner
                .rpc_server_handles()
                .ops
                .as_ref()
                .expect("ops server should be running")
                .local_addr()
        )
    };
}

/// Bundle of values pulled from a live node that any happy-path envelope needs.
struct LiveEnvelopeFields {
    recent_block_hash: B256,
    expires_at_block: u64,
    validator_id: B256,
    next_nonce: u64,
}

async fn fetch_live_envelope_fields(
    eth_client: &HttpClient,
    ops_client: &HttpClient,
) -> LiveEnvelopeFields {
    let (recent_block_hash, recent_block_number) = latest_block(eth_client).await;
    let validator_id = ops_get_validator_id(ops_client).await;
    let admin_nonce = ops_get_admin_nonce(ops_client).await;
    LiveEnvelopeFields {
        recent_block_hash,
        // Generous window inside the 256-block bound.
        expires_at_block: recent_block_number + 128,
        validator_id,
        next_nonce: admin_nonce + 1,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_whitelist_from_governance_key_both_payload_forms() {
    // Sentinel interception must cover BOTH payload forms of eth_sendRawTransaction:
    // raw RLP bytes and EIP-712 typed data (which the server re-encodes to RLP so it
    // flows through the same decode + sentinel pipeline). Interleaving the two forms
    // against one node proves they drive the same whitelist and admin-nonce state
    // machine: raw whitelist -> typed revoke -> typed whitelist -> raw revoke, all
    // consuming one shared nonce sequence. A regression that routes typed-data
    // submissions around the sentinel check would surface here as a pool insertion
    // (hash visible via eth_getTransactionByHash) and a missing whitelist mutation.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let rpc_url = node.rpc_url().to_string();
    let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
    let ops_url = node_ops_url!(node);
    let ops_client = build_ops_client(&ops_url);
    let chain_id = 5124u64;

    // Envelope: fetch live validator_id, admin_nonce, recent block once; later
    // sentinels reuse it with incremented admin nonces.
    let before = ops_get_admin_nonce(&ops_client).await;
    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let whitelist_env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: live.next_nonce,
    };
    let expires_at = FAR_FUTURE_BLOCK;

    // 1. Whitelist via raw bytes.
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), expires_at, whitelist_env),
    );
    submit_sentinel(&client, &raw_tx).await.expect("raw-bytes whitelist sentinel should succeed");
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        before + 1,
        "raw-bytes whitelist must advance admin_nonce"
    );
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 1);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("0"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "whitelisted reader should be able to read storage"
    );

    // 2. Revoke via typed data, continuing the same admin-nonce sequence.
    let revoke_env = Envelope { nonce: whitelist_env.nonce + 1, ..whitelist_env };
    let (typed, _hash) = build_sentinel_typed_data_tx(
        &governance,
        chain_id,
        revoke_calldata(reader.address(), revoke_env),
        revoke_env,
    );
    submit_sentinel_typed_data(&client, &typed)
        .await
        .expect("typed-data revoke sentinel should succeed");
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        before + 2,
        "typed-data revoke must advance admin_nonce"
    );
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 2);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("1"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "reader revoked via typed data should be rejected"
    );

    // 3. Whitelist again via typed data.
    let rewhitelist_env = Envelope { nonce: whitelist_env.nonce + 2, ..whitelist_env };
    let (typed, expected_hash) = build_sentinel_typed_data_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), expires_at, rewhitelist_env),
        rewhitelist_env,
    );
    let returned = submit_sentinel_typed_data(&client, &typed)
        .await
        .expect("typed-data whitelist sentinel should succeed");
    assert_eq!(
        returned.parse::<B256>().expect("parse returned tx hash"),
        expected_hash,
        "node must report the intercepted tx's own hash"
    );
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        before + 3,
        "typed-data whitelist must advance admin_nonce"
    );
    // The ops server's per-key replay nonce is an exact-increment counter consumed
    // only by AUTHORIZED reads: the revoked attempt above was rejected at the
    // whitelist check before nonce consumption, so this is still the reader's
    // second consumed nonce.
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 3);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("1"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "reader re-whitelisted via typed data should read storage"
    );

    // Sentinel txs are node-local: they must not enter the txpool (or a block),
    // so the node has no record of the hash it just returned.
    let pooled: Option<serde_json::Value> = client
        .request("eth_getTransactionByHash", rpc_params![expected_hash])
        .await
        .expect("eth_getTransactionByHash");
    assert!(pooled.is_none(), "sentinel tx must not enter the txpool, got: {pooled:?}");

    // 4. Revoke via raw bytes, closing the loop on the shared nonce sequence.
    let final_env = Envelope { nonce: whitelist_env.nonce + 3, ..whitelist_env };
    let raw_tx =
        build_sentinel_tx(&governance, chain_id, revoke_calldata(reader.address(), final_env));
    submit_sentinel(&client, &raw_tx).await.expect("raw-bytes revoke sentinel should succeed");
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 4);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("2"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "reader revoked via raw bytes should be rejected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_whitelist_from_non_governance_key_fails_both_payload_forms() {
    // The governance-signer check must hold regardless of which payload form
    // carried the sentinel action, so the same attacker-signed action is
    // submitted both as raw RLP bytes and as EIP-712 typed data.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let attacker = PrivateKeySigner::random();
    let target = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let rpc_url = node.rpc_url().to_string();
    let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    // Envelope is otherwise valid — only the signer is wrong.
    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: live.next_nonce,
    };
    let expires_at = FAR_FUTURE_BLOCK;
    let raw_tx = build_sentinel_tx(
        &attacker,
        chain_id,
        whitelist_calldata(target.address(), expires_at, env),
    );
    let err = submit_sentinel(&client, &raw_tx)
        .await
        .expect_err("non-governance raw-bytes sentinel should be rejected");
    assert!(err.contains("unauthorized"), "expected unauthorized signer error, got: {err}");

    let (typed, _hash) = build_sentinel_typed_data_tx(
        &attacker,
        chain_id,
        whitelist_calldata(target.address(), expires_at, env),
        env,
    );
    let err = submit_sentinel_typed_data(&client, &typed)
        .await
        .expect_err("non-governance typed-data sentinel should be rejected");
    assert!(err.contains("unauthorized"), "expected unauthorized signer error, got: {err}");

    // No whitelist mutation happened through either form.
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        0,
        "rejected sentinels must not advance admin_nonce"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejects_wrong_validator_id() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: B256::random(), // wrong
        nonce: live.next_nonce,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    let err =
        submit_sentinel(&client, &raw_tx).await.expect_err("wrong validator_id should be rejected");
    assert!(err.contains("validator_id mismatch"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejects_non_canonical_recent_block_hash() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: B256::random(), // not on canonical chain
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: live.next_nonce,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    let err = submit_sentinel(&client, &raw_tx)
        .await
        .expect_err("non-canonical recent_block_hash should be rejected");
    assert!(err.contains("not on canonical chain"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejects_block_range_over_bound() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let (recent_block_hash, recent_block_number) = latest_block(&client).await;
    let validator_id = ops_get_validator_id(&ops_client).await;
    let next_nonce = ops_get_admin_nonce(&ops_client).await + 1;
    let env = Envelope {
        recent_block_hash,
        // MAX_SENTINEL_BLOCK_RANGE is 256 in transaction.rs; 257 must trip the bound.
        expires_at_block: recent_block_number + 257,
        validator_id,
        nonce: next_nonce,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    let err = submit_sentinel(&client, &raw_tx)
        .await
        .expect_err("range > MAX_SENTINEL_BLOCK_RANGE should be rejected");
    assert!(err.contains("block range exceeds bound"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejects_expired_against_head() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (mut node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let (recent_block_hash, recent_block_number) = latest_block(&client).await;
    let validator_id = ops_get_validator_id(&ops_client).await;
    let next_nonce = ops_get_admin_nonce(&ops_client).await + 1;
    // expires_at_block == recent_block_number, so advancing one block makes head > expires.
    let env = Envelope {
        recent_block_hash,
        expires_at_block: recent_block_number,
        validator_id,
        nonce: next_nonce,
    };

    // Advance the chain so current head exceeds expires_at_block.
    node.advance_block().await.expect("advance block");

    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    let err =
        submit_sentinel(&client, &raw_tx).await.expect_err("expired sentinel should be rejected");
    assert!(err.contains("has expired"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejects_replayed_nonce() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: live.next_nonce,
    };
    let expires_at = FAR_FUTURE_BLOCK;
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), expires_at, env),
    );

    // First submission must succeed.
    submit_sentinel(&client, &raw_tx).await.expect("first submission");

    // Second submission with the same envelope must be rejected by the nonce check.
    let err =
        submit_sentinel(&client, &raw_tx).await.expect_err("replayed envelope should be rejected");
    assert!(err.contains("nonce has already been consumed"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_bootstrap_endpoints_are_unauthenticated() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));

    // Unauthenticated reads succeed.
    let validator_id = ops_get_validator_id(&ops_client).await;
    assert_ne!(validator_id, B256::ZERO, "validator_id must be a fresh random value");
    let admin_nonce = ops_get_admin_nonce(&ops_client).await;
    assert_eq!(admin_nonce, 0, "admin nonce starts at 0 on a fresh node");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_admin_nonce_advances_after_successful_sentinel_tx() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let before = ops_get_admin_nonce(&ops_client).await;

    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: before + 1,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    submit_sentinel(&client, &raw_tx).await.expect("whitelist sentinel tx should succeed");

    let after = ops_get_admin_nonce(&ops_client).await;
    assert_eq!(after, before + 1, "admin_nonce must advance to the consumed value");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejects_expires_before_reference() {
    // Distinct from the range-exceeded and expired-by-head arms: this is the
    // `expires_at_block < reference_block_number` sub-arm of check #3, which
    // catches envelopes built with a reference newer than the expiry.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (mut node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    // Advance two blocks so the reference can be > 0.
    node.advance_block().await.expect("advance #1");
    node.advance_block().await.expect("advance #2");

    let (recent_block_hash, recent_block_number) = latest_block(&client).await;
    assert!(recent_block_number >= 2, "need a positive reference block");
    let validator_id = ops_get_validator_id(&ops_client).await;
    let next_nonce = ops_get_admin_nonce(&ops_client).await + 1;
    let env = Envelope {
        recent_block_hash,
        // Strictly less than the reference. Must trip the "precedes" arm
        // before the "expired" arm has a chance to fire.
        expires_at_block: recent_block_number - 1,
        validator_id,
        nonce: next_nonce,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    let err = submit_sentinel(&client, &raw_tx)
        .await
        .expect_err("expires_at_block < reference should be rejected");
    assert!(err.contains("precedes reference block"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_accepts_admin_nonce_gap_jump() {
    // The strict-greater rule means the first envelope doesn't have to be
    // nonce=1; a large initial value is fine. Subsequent envelopes must still
    // be strictly greater, and anything lower (including values inside the
    // jumped-over range) is silently dropped as a stale/replay payload.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let live = fetch_live_envelope_fields(&client, &ops_client).await;

    // Jump from initial admin_nonce=0 straight to 100.
    let env_jump = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: 100,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env_jump),
    );
    submit_sentinel(&client, &raw_tx).await.expect("gap-jump sentinel should succeed");
    assert_eq!(ops_get_admin_nonce(&ops_client).await, 100);

    // A nonce inside the jumped-over range must now be rejected as consumed.
    let env_stale = Envelope { nonce: 50, ..env_jump };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env_stale),
    );
    let err = submit_sentinel(&client, &raw_tx)
        .await
        .expect_err("nonce below the jumped value must be rejected");
    assert!(err.contains("nonce has already been consumed"), "got: {err}");

    // A strictly greater nonce continues to work.
    let env_next = Envelope { nonce: 101, ..env_jump };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env_next),
    );
    submit_sentinel(&client, &raw_tx).await.expect("strictly-greater follow-up should succeed");
    assert_eq!(ops_get_admin_nonce(&ops_client).await, 101);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_non_bootstrap_method_requires_signature() {
    // The bootstrap-method allowlist (ops_getValidatorId / ops_getAdminNonce)
    // must NOT cover any other ops_* method. Sending ops_getStorageAt without
    // an X-Signature header must be rejected with 400 by the auth path.
    // Also confirms the matches! arm is exact-match and not substring-prone.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let ops_url = node_ops_url!(node);

    // (a) ops_getStorageAt without any signature header.
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 1);
    let resp = reqwest::Client::new()
        .post(&ops_url)
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("post ops_getStorageAt");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "ops_getStorageAt without X-Signature must be 400"
    );

    // (b) Method that contains "ops_getValidatorId" as a substring but isn't an
    // exact match must still hit the auth path. Defends against a careless
    // refactor that swaps `matches!` for `contains()`.
    let lookalike_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_getValidatorIdEvil",
        "params": [],
        "id": 1,
    })
    .to_string();
    let resp = reqwest::Client::new()
        .post(&ops_url)
        .header("Content-Type", "application/json")
        .body(lookalike_body)
        .send()
        .await
        .expect("post lookalike method");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "method that merely contains a bootstrap-method substring must still require auth"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_does_not_burn_nonce_on_action_validation_failure() {
    // Action-level validation (here: `expires_at` not in the future) runs before
    // the admin_nonce advance, so a typo doesn't force governance to refetch the
    // nonce and re-sign. Same envelope nonce must work on retry with a corrected
    // expires_at.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    let before = ops_get_admin_nonce(&ops_client).await;
    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: live.next_nonce,
    };

    // 1. Submit with a stale `key_expires_at_block` (at/below current head) — must be rejected.
    //    Current head is at most a few blocks ahead of 0 on this fresh dev chain.
    let stale_key_expires_at_block = 0u64;
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), stale_key_expires_at_block, env),
    );
    let err = submit_sentinel(&client, &raw_tx)
        .await
        .expect_err("stale key_expires_at_block should be rejected");
    assert!(err.contains("key_expires_at_block must be in the future"), "got: {err}");

    // 2. admin_nonce must NOT have advanced.
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        before,
        "action-validation failure must not burn a nonce",
    );

    // 3. Resubmit with the same envelope nonce and a valid expires_at — must succeed.
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );
    submit_sentinel(&client, &raw_tx)
        .await
        .expect("retry with same nonce and valid expires_at should succeed");
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        before + 1,
        "successful retry must advance admin_nonce exactly once",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_rejected_by_send_raw_transaction_sync() {
    // eth_sendRawTransactionSync waits for on-chain inclusion. Sentinel txs are
    // intercepted at the RPC layer and never enter the pool or a block, so the
    // sync endpoint must reject them immediately rather than time out at 30s
    // (the upstream default).
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_client = build_ops_client(&node_ops_url!(node));
    let chain_id = 5124u64;

    // Build a perfectly valid sentinel envelope — only the endpoint is wrong.
    let live = fetch_live_envelope_fields(&client, &ops_client).await;
    let env = Envelope {
        recent_block_hash: live.recent_block_hash,
        expires_at_block: live.expires_at_block,
        validator_id: live.validator_id,
        nonce: live.next_nonce,
    };
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), FAR_FUTURE_BLOCK, env),
    );

    // Time the round-trip so we can prove it's the early-reject path, not a 30s timeout.
    let started = std::time::Instant::now();
    let hex = format!("0x{}", alloy_primitives::hex::encode(&raw_tx));
    let result = client
        .request::<serde_json::Value, _>("eth_sendRawTransactionSync", rpc_params![hex])
        .await;
    let elapsed = started.elapsed();

    let err = result.expect_err("sentinel tx via sendRawTransactionSync must be rejected");
    let err_str = err.to_string();
    assert!(
        err_str.contains("not supported via eth_sendRawTransactionSync"),
        "expected explicit rejection message, got: {err_str}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "rejection must be immediate; the upstream timeout is 30s. elapsed: {elapsed:?}"
    );

    // The whitelist mutation must NOT have applied — admin_nonce stays at 0.
    assert_eq!(
        ops_get_admin_nonce(&ops_client).await,
        0,
        "rejected sentinel must not advance admin_nonce",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_whitelisted_key_expires_when_head_passes_key_block() {
    // Full TEE-safe expiry flow exercised through the sentinel-tx path (not by
    // calling `whitelist.add` directly): governance whitelists a key until a
    // specific block, the reader can read until the chain advances past that
    // block, and is then rejected. Confirms the validator's view of expiry is
    // bound to canonical head, not host wall clock.
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (mut node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let client = HttpClientBuilder::default().build(&node.rpc_url().to_string()).unwrap();
    let ops_url = node_ops_url!(node);
    let ops_client = build_ops_client(&ops_url);
    let chain_id = 5124u64;

    // Whitelist the reader until block 3. Current head is 0; the entry must be
    // valid for the next read but rejected after we mine three blocks.
    let (recent_block_hash, recent_block_number) = latest_block(&client).await;
    assert_eq!(recent_block_number, 0, "fresh chain head must start at 0");
    let validator_id = ops_get_validator_id(&ops_client).await;
    let next_nonce = ops_get_admin_nonce(&ops_client).await + 1;
    let env = Envelope {
        recent_block_hash,
        // generous envelope window — independent of the entry's own expiry
        expires_at_block: recent_block_number + 128,
        validator_id,
        nonce: next_nonce,
    };
    let key_expires_at_block: u64 = 3;
    let raw_tx = build_sentinel_tx(
        &governance,
        chain_id,
        whitelist_calldata(reader.address(), key_expires_at_block, env),
    );
    submit_sentinel(&client, &raw_tx).await.expect("whitelist sentinel should succeed");

    // While head is still below `key_expires_at_block`, the reader can read.
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 1);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("0"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "reader must be authorized before head reaches key_expires_at_block"
    );

    // Advance the chain past `key_expires_at_block`. After 3 blocks
    // `best_block_number() == 3 == key_expires_at_block`, which fails the
    // strict-less check, so the entry is now expired.
    for _ in 0..3 {
        node.advance_block().await.expect("advance block");
    }
    let (_after_hash, after_number) = latest_block(&client).await;
    assert!(after_number >= key_expires_at_block, "head must reach the expiry block");

    // Reader is now rejected — entry has expired.
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 2);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("1"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "reader must be rejected once head reaches key_expires_at_block"
    );
}
