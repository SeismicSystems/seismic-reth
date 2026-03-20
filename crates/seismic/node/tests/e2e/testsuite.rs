use alloy_consensus::BlockHeader;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_rpc_types_eth::TransactionRequest;
use eyre::Result;
use reth_e2e_test_utils::{setup, transaction::TransactionTestContext};
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_node::{node::SeismicNode, purpose_keys::init_purpose_keys};
use seismic_enclave::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk, GetPurposeKeysResponse,
};
use std::sync::Once;

/// Ensure mock purpose keys are initialized exactly once per test binary.
/// In production this happens in main.rs after booting the enclave.
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
/// Uses `setup` + `advance_block` (internal engine channel) rather than the
/// testsuite `ProduceBlocks` action, which goes through JSON-RPC `new_payload_v3`
/// and loses `requests_hash` (Prague field) during the V3 round-trip.
///
/// Currently ignored: `advance_block` → `wait_for_built_payload` hangs after
/// the first block is built. The payload builder correctly seals a block with
/// the tx included (`gas_used`: 21000) but `best_payload` never resolves.
/// Root cause TBD — may be related to how `SEISMIC_DEV` interacts with the
/// payload resolver or the `setup` (non-engine) path.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "advance_block hangs in wait_for_built_payload — payload builds correctly but resolver doesn't complete"]
async fn test_seismic_produce_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) =
        setup::<SeismicNode>(1, SEISMIC_DEV.clone(), false, seismic_payload_attributes).await?;
    let mut node = nodes.pop().unwrap();

    // Produce 3 blocks, each with a transfer tx at incrementing nonces.
    // advance() passes the block index (0, 1, 2) as the nonce argument.
    let chain_id = wallet.chain_id;
    let signer = wallet.inner;
    let chain = node
        .advance(3, |nonce| {
            let w = signer.clone();
            Box::pin(async move {
                let tx = TransactionRequest {
                    nonce: Some(nonce),
                    value: Some(U256::from(100)),
                    to: Some(alloy_primitives::TxKind::Call(Address::random())),
                    gas: Some(21000),
                    max_fee_per_gas: Some(20e9 as u128),
                    max_priority_fee_per_gas: Some(20e9 as u128),
                    chain_id: Some(chain_id),
                    ..Default::default()
                };
                let signed = TransactionTestContext::sign_tx(w, tx).await;
                signed.encoded_2718().into()
            })
        })
        .await?;

    assert_eq!(chain.len(), 3, "should have produced 3 blocks");
    for (i, payload) in chain.iter().enumerate() {
        assert_eq!(payload.block().number(), (i + 1) as u64, "block number should match");
    }

    Ok(())
}
