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

const SEISMIC_TIMESTAMP_MULTIPLIER: u64 = 1000; // Seismic returns times in milliseconds

fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp: timestamp * SEISMIC_TIMESTAMP_MULTIPLIER,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

// Produces a single block on a Seismic node using the internal engine channel
// (not the JSON-RPC engine API, which loses Prague-era fields in V3 payloads).
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_produce_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup_engine::<SeismicNode>(
        1,
        SEISMIC_DEV.clone(),
        false,
        Default::default(),
        seismic_payload_attributes,
    )
    .await?;
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
