//! E2E test for the locally built pending block returned by `eth_getBlockByNumber("pending")`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test file - panics are acceptable

use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_e2e_test_utils::{
    node::NodeTestContext, transaction::TransactionTestContext, wallet::Wallet,
};
use reth_node_builder::{EngineNodeLauncher, Node, NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use reth_rpc_builder::RpcModuleSelection;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_node::{
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, seismic_payload_attributes, SeismicTestNode},
};
use reth_tasks::TaskManager;

/// Launches a single Seismic node on the dev chain spec with an HTTP-only RPC
/// server. The test only talks HTTP, so the IPC endpoint (which binds a socket
/// under the global temp dir) is disabled.
async fn launch_http_node() -> eyre::Result<(SeismicTestNode, TaskManager, Wallet)> {
    let tasks = TaskManager::current();
    let exec = tasks.executor();

    ensure_mock_purpose_keys();

    let mut rpc_args = RpcServerArgs::default()
        .with_unused_ports()
        .with_http()
        .with_http_api(RpcModuleSelection::All);
    rpc_args.ipcdisable = true;

    let node_config = NodeConfig::new(SEISMIC_DEV.clone()).with_unused_ports().with_rpc(rpc_args);

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

    let node = NodeTestContext::new(node, seismic_payload_attributes).await?;
    let wallet = Wallet::default().with_chain_id(5124);

    Ok((node, tasks, wallet))
}

/// Parses a hex quantity field (`"0x..."`) from a JSON block response.
fn hex_field(block: &serde_json::Value, field: &str) -> u64 {
    let raw = block[field].as_str().unwrap_or_else(|| panic!("missing block field: {field}"));
    u64::from_str_radix(raw.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("invalid hex quantity for {field}: {raw}"))
}

/// The pending block is built locally on top of the latest block, advancing the
/// timestamp by one 12-second slot. Header timestamps are in milliseconds by
/// default and in seconds with the `timestamp-in-seconds` feature, so the
/// expected offset is 12000 or 12 respectively. This guards the feature
/// forwarding into the RPC crates: if `reth-rpc-eth-api` were built without the
/// feature in a seconds-mode node, the offset would be 12000 instead of 12.
#[tokio::test(flavor = "multi_thread")]
async fn test_pending_block_timestamp_offset() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (node, _tasks, wallet) = launch_http_node().await?;
    let client = HttpClientBuilder::default().build(node.rpc_url())?;

    // Put a transfer in the pool so the pending block is genuinely built from
    // the mempool rather than echoing an existing block.
    let raw_tx =
        TransactionTestContext::transfer_tx_bytes(wallet.chain_id, wallet.inner.clone()).await;
    let tx_hash: String = client
        .request(
            "eth_sendRawTransaction",
            rpc_params![format!("0x{}", alloy_primitives::hex::encode(&raw_tx))],
        )
        .await
        .expect("eth_sendRawTransaction");

    let latest: serde_json::Value =
        client.request("eth_getBlockByNumber", rpc_params!["latest", false]).await?;
    let pending: serde_json::Value =
        client.request("eth_getBlockByNumber", rpc_params!["pending", false]).await?;

    // The pending block extends the latest block and includes the pooled tx.
    assert_eq!(hex_field(&pending, "number"), hex_field(&latest, "number") + 1);
    let pending_txs = pending["transactions"].as_array().expect("pending block tx list");
    assert!(
        pending_txs.iter().any(|tx| tx.as_str() == Some(tx_hash.as_str())),
        "pending block should contain the pooled transaction {tx_hash}, got {pending_txs:?}"
    );

    let expected_offset: u64 = if cfg!(feature = "timestamp-in-seconds") { 12 } else { 12_000 };
    assert_eq!(
        hex_field(&pending, "timestamp"),
        hex_field(&latest, "timestamp") + expected_offset,
        "pending block timestamp should advance by exactly one slot"
    );

    Ok(())
}
