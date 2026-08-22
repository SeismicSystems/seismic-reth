use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_eth::TransactionRequest;
use eyre::Result;
use jsonrpsee::http_client::HttpClientBuilder;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_seismic_node::utils::e2e::ensure_mock_purpose_keys;
use reth_seismic_rpc::ext::SeismicApiClient;
use reth_transaction_pool::TransactionPool;

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_node_info() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, _wallet) = reth_seismic_node::utils::e2e::setup(1).await?;
    let node = nodes.pop().unwrap();
    let expected_node_record = node.network.record();
    let client = HttpClientBuilder::default().build(node.rpc_url().as_str())?;

    let node_info = SeismicApiClient::node_info(&client).await?;
    assert_eq!(node_info.node_record, expected_node_record);

    Ok(())
}

// Produces a single block on a Seismic node using the internal engine channel
// (not the JSON-RPC engine API, which loses Prague-era fields in V3 payloads).
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_produce_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = reth_seismic_node::utils::e2e::setup(1).await?;
    let mut node = nodes.pop().unwrap();

    let tx = TransactionRequest {
        nonce: Some(0),
        value: Some(U256::from(100)),
        to: Some(alloy_primitives::TxKind::Call(Address::random())),
        gas: Some(21000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(20e9 as u128),
        chain_id: Some(wallet.chain_id),
        ..Default::default()
    };
    let signed = TransactionTestContext::sign_tx(wallet.inner.clone(), tx).await;
    let raw_tx: alloy_primitives::Bytes = signed.encoded_2718().into();

    let tx_hash = node.rpc.inject_tx(raw_tx).await?;
    let payload = node.advance_block().await?;
    node.assert_new_block(tx_hash, payload.block().hash(), payload.block().number).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_blob_sidecar_survives_pool_ingress() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = reth_seismic_node::utils::e2e::setup(1).await?;
    let node = nodes.pop().unwrap();
    let raw_tx =
        TransactionTestContext::tx_with_blobs_bytes(wallet.chain_id, wallet.inner.clone()).await?;

    let tx_hash = node.rpc.inject_tx(raw_tx).await?;

    assert!(node.inner.pool.get_blob(tx_hash)?.is_some());
    Ok(())
}
