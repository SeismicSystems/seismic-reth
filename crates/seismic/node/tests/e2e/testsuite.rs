use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_rpc_types_eth::TransactionRequest;
use eyre::Result;
use reth_e2e_test_utils::{setup_engine, transaction::TransactionTestContext};
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_node::{node::SeismicNode, purpose_keys::init_purpose_keys};
use seismic_enclave::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk, GetPurposeKeysResponse,
};
use std::sync::Once;

/// Ensure mock purpose keys are initialized exactly once per test binary.
static INIT_KEYS: Once = Once::new();
fn ensure_mock_purpose_keys() {
    INIT_KEYS.call_once(|| {
        init_purpose_keys(GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        });
    });
}

fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    // Seismic uses millisecond timestamps internally (when timestamp-in-seconds feature is
    // disabled)
    let timestamp = timestamp * 1000;
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Test that a Seismic node can produce and finalize blocks.
///
/// Inlines the `advance_block` logic with debug tracing at each step
/// to diagnose where the test hangs in CI.
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_produce_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    tracing::info!(target: "seismic::testsuite", "setting up node");
    let (mut nodes, _tasks, wallet) = setup_engine::<SeismicNode>(
        1,
        SEISMIC_DEV.clone(),
        false,
        Default::default(),
        seismic_payload_attributes,
    )
    .await?;
    let mut node = nodes.pop().unwrap();
    tracing::info!(target: "seismic::testsuite", chain_id = wallet.chain_id, "node ready");

    // Build and inject a single transfer tx
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

    tracing::info!(target: "seismic::testsuite", "injecting tx");
    let tx_hash = node.rpc.inject_tx(raw_tx).await?;
    tracing::info!(target: "seismic::testsuite", ?tx_hash, "tx injected");

    // Step 1: trigger payload building via new_payload
    // This calls: payload.new_payload() → expect_attr_event → wait_for_built_payload →
    // expect_built_payload
    tracing::info!(target: "seismic::testsuite", "triggering payload build (new_payload)");
    let eth_attr = node.payload.new_payload().await.unwrap();
    tracing::info!(target: "seismic::testsuite", payload_id = ?eth_attr.payload_id(), "payload attributes created, waiting for attr event");

    node.payload.expect_attr_event(eth_attr.clone()).await?;
    tracing::info!(target: "seismic::testsuite", "attr event received, waiting for built payload");

    node.payload.wait_for_built_payload(eth_attr.payload_id()).await;
    tracing::info!(target: "seismic::testsuite", "built payload ready, expecting built payload event");

    let payload = node.payload.expect_built_payload().await?;
    tracing::info!(target: "seismic::testsuite", block_number = payload.block().number, block_hash = ?payload.block().hash(), "payload built");

    // Step 2: submit payload to engine
    tracing::info!(target: "seismic::testsuite", "submitting payload");
    node.submit_payload(payload.clone()).await?;
    tracing::info!(target: "seismic::testsuite", "payload submitted");

    // Step 3: update forkchoice
    tracing::info!(target: "seismic::testsuite", "updating forkchoice");
    node.update_forkchoice(payload.block().hash(), payload.block().hash()).await?;
    tracing::info!(target: "seismic::testsuite", "forkchoice updated");

    // Step 4: verify
    tracing::info!(target: "seismic::testsuite", "verifying block");
    node.assert_new_block(tx_hash, payload.block().hash(), payload.block().number).await?;
    tracing::info!(target: "seismic::testsuite", "PASS - block 1 produced and verified");

    Ok(())
}
