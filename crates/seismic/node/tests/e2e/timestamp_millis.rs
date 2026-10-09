//! Sub-second block timestamps: header field, Engine API round trip, consensus ordering and the
//! public RPC shape.

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_eth::TransactionRequest;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_engine_primitives::PayloadValidator;
use reth_payload_primitives::PayloadTypes;
use reth_seismic_engine_primitives::MILLIS_PER_SECOND;
use reth_seismic_node::{
    consensus::validate_against_parent_timestamp_millis,
    engine::{SeismicEngineTypes, SeismicEngineValidator},
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, seismic_payload_attributes_millis, test_chain_spec},
};
use serde_json::Value;

/// Every test block lands in this second; the harness's increasing attribute timestamp becomes
/// the sub-second component.
const BASE_SECONDS: u64 = 1_800_000_000;

fn quantity(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn sub_second_blocks_round_trip_through_engine_consensus_and_rpc() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let chain_spec = test_chain_spec();
    let (mut nodes, _tasks, wallet) = reth_e2e_test_utils::setup_engine::<SeismicNode>(
        1,
        chain_spec.clone(),
        false,
        Default::default(),
        |timestamp| {
            // The harness starts at a fixed seconds timestamp and increments by one per block;
            // fold that into the millisecond part so consecutive blocks share a second.
            seismic_payload_attributes_millis(
                BASE_SECONDS * MILLIS_PER_SECOND + (timestamp % 100) * 7,
            )
        },
    )
    .await?;
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url())?;

    let mut headers = Vec::new();
    for nonce in 0..3u64 {
        let tx = TransactionRequest {
            nonce: Some(nonce),
            value: Some(U256::from(1)),
            to: Some(Address::random().into()),
            gas: Some(21_000),
            max_fee_per_gas: Some(20_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            chain_id: Some(wallet.chain_id),
            ..Default::default()
        };
        let signed = TransactionTestContext::sign_tx(wallet.inner.clone(), tx).await;
        let hash = node
            .rpc
            .inject_tx(alloy_eips::eip2718::Encodable2718::encoded_2718(&signed).into())
            .await?;
        let payload = node.advance_block().await?;
        let block = payload.block().clone();
        node.assert_new_block(hash, block.hash(), block.number()).await?;

        // The built header carries the attributes' split timestamp.
        assert_eq!(block.timestamp(), BASE_SECONDS, "seconds part");
        assert!(block.header().timestamp_millis_part < MILLIS_PER_SECOND);
        assert_eq!(
            block.header().timestamp_millis(),
            BASE_SECONDS * MILLIS_PER_SECOND + block.header().timestamp_millis_part
        );

        // Engine API round trip: the payload carries the part and rebuilds the same block/hash.
        let execution_data = SeismicEngineTypes::block_to_payload(block.clone());
        assert_eq!(
            execution_data.payload.timestamp_millis_part,
            block.header().timestamp_millis_part
        );
        assert_eq!(execution_data.payload.timestamp(), BASE_SECONDS);
        let validator = SeismicEngineValidator::new(chain_spec.clone());
        let rebuilt = PayloadValidator::<SeismicEngineTypes>::ensure_well_formed_payload(
            &validator,
            execution_data,
        )?;
        assert_eq!(rebuilt.hash(), block.hash());
        assert_eq!(rebuilt.header(), block.header());

        // Public RPC: `timestamp` is the standard seconds field, the part is its own field.
        let rpc_block: Value = client
            .request("eth_getBlockByNumber", rpc_params![format!("{:#x}", block.number()), false])
            .await?;
        assert_eq!(quantity(&rpc_block["timestamp"]), BASE_SECONDS);
        assert_eq!(
            quantity(&rpc_block["timestampMillisPart"]),
            block.header().timestamp_millis_part
        );
        assert_eq!(
            rpc_block["hash"].as_str().unwrap().parse::<alloy_primitives::B256>()?,
            block.hash()
        );

        headers.push(block.header().clone());
    }

    // Consecutive blocks within the same second were accepted; the consensus rule orders
    // them by millisecond and rejects the reverse.
    for pair in headers.windows(2) {
        assert_eq!(pair[0].timestamp(), pair[1].timestamp());
        assert!(pair[1].timestamp_millis() > pair[0].timestamp_millis());
        assert!(validate_against_parent_timestamp_millis(&pair[1], &pair[0]).is_ok());
        assert!(validate_against_parent_timestamp_millis(&pair[0], &pair[1]).is_err());
    }

    // A genesis block has a zero part, and the chain spec's hash is the Seismic header hash.
    let genesis: Value = client.request("eth_getBlockByNumber", rpc_params!["0x0", false]).await?;
    assert_eq!(quantity(&genesis["timestampMillisPart"]), 0);
    assert_eq!(
        genesis["hash"].as_str().unwrap().parse::<alloy_primitives::B256>()?,
        chain_spec.genesis_hash()
    );

    Ok(())
}
