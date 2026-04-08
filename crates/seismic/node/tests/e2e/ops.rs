//! E2E tests for ops whitelist/revoke via sentinel transactions in `eth_sendRawTransaction`.

use alloy_consensus::SignableTransaction;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
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
use std::sync::Arc;

sol! {
    interface OpsWhitelistTxAuth {
        function whitelistKey(address target, uint64 expiresAt) external;
        function revokeKey(address target) external;
    }
}

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

fn whitelist_calldata(target: Address, expires_at: u64) -> Bytes {
    OpsWhitelistTxAuth::whitelistKeyCall { target, expiresAt: expires_at }.abi_encode().into()
}

fn revoke_calldata(target: Address) -> Bytes {
    OpsWhitelistTxAuth::revokeKeyCall { target }.abi_encode().into()
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
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
    rpc_args.ops_port = 0; // random unused port

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

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_whitelist_from_governance_key() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let rpc_url = node.rpc_url().to_string();
    let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
    let chain_id = 5124u64;

    // Send a whitelist sentinel tx from governance key.
    let expires_at = current_unix_timestamp() + 3600;
    let raw_tx =
        build_sentinel_tx(&governance, chain_id, whitelist_calldata(reader.address(), expires_at));
    let result: serde_json::Value = client
        .request(
            "eth_sendRawTransaction",
            rpc_params![format!("0x{}", alloy_primitives::hex::encode(&raw_tx))],
        )
        .await
        .expect("whitelist sentinel tx should succeed");
    assert!(result.is_string(), "should return a tx hash");

    // Now verify the reader is whitelisted by querying the ops server.
    let ops_url = format!(
        "http://{}",
        node.inner
            .rpc_server_handles()
            .ops
            .as_ref()
            .expect("ops server should be running")
            .local_addr()
    );
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 1);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("0"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "whitelisted reader should be able to read storage"
    );

    // Send a revoke sentinel tx.
    let raw_tx = build_sentinel_tx(&governance, chain_id, revoke_calldata(reader.address()));
    let result: serde_json::Value = client
        .request(
            "eth_sendRawTransaction",
            rpc_params![format!("0x{}", alloy_primitives::hex::encode(&raw_tx))],
        )
        .await
        .expect("revoke sentinel tx should succeed");
    assert!(result.is_string(), "should return a tx hash");

    // Reader should no longer be whitelisted.
    let body = ops_get_storage_request(PARAMS_CONTRACT, alloy_primitives::B256::ZERO, 2);
    let resp = send_ops_signed_request(&ops_url, &body, &reader, Some("1"), chain_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "revoked reader should be rejected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_sentinel_whitelist_from_non_governance_key_fails() {
    reth_tracing::init_test_tracing();
    let governance = PrivateKeySigner::random();
    let attacker = PrivateKeySigner::random();
    let target = PrivateKeySigner::random();

    let (node, _tasks, _wallet) = launch_ops_node(&governance).await.unwrap();
    let rpc_url = node.rpc_url().to_string();
    let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
    let chain_id = 5124u64;

    // Attacker tries to send a whitelist sentinel tx — should fail.
    let expires_at = current_unix_timestamp() + 3600;
    let raw_tx =
        build_sentinel_tx(&attacker, chain_id, whitelist_calldata(target.address(), expires_at));
    let result = client
        .request::<serde_json::Value, _>(
            "eth_sendRawTransaction",
            rpc_params![format!("0x{}", alloy_primitives::hex::encode(&raw_tx))],
        )
        .await;
    assert!(result.is_err(), "non-governance sentinel tx should be rejected");
}
