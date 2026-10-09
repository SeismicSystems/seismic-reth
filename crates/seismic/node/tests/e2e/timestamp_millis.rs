//! Sub-second block timestamps: header field, Engine API round trip, consensus ordering and the
//! public RPC shape.

use alloy_consensus::BlockHeader;
use alloy_primitives::{address, bytes, Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types_engine::{
    ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadStatus,
};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_engine_primitives::PayloadValidator;
use reth_payload_primitives::PayloadTypes;
use reth_seismic_engine_primitives::{
    SeismicExecutionPayloadEnvelopeV4, SeismicPayloadAttributes, SeismicPayloadBuilderAttributes,
    MILLIS_PER_SECOND,
};
use reth_seismic_node::{
    consensus::validate_against_parent_timestamp_millis,
    engine::{SeismicEngineTypes, SeismicEngineValidator},
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, test_chain_spec},
};
use serde_json::Value;

/// Every test block lands in this second; the harness's increasing attribute timestamp becomes
/// the sub-second component.
const BASE_SECONDS: u64 = 1_800_000_000;

fn payload_attributes(timestamp: u64, part: u64) -> SeismicPayloadAttributes {
    SeismicPayloadAttributes::new(
        PayloadAttributes {
            timestamp,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: Address::ZERO,
            withdrawals: Some(vec![]),
            parent_beacon_block_root: Some(B256::from(
                U256::from(timestamp * MILLIS_PER_SECOND + part).to_be_bytes::<32>(),
            )),
        },
        part,
    )
}

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
            SeismicPayloadBuilderAttributes::new(
                B256::ZERO,
                payload_attributes(BASE_SECONDS, (timestamp % 100) * 7),
            )
            .unwrap()
        },
    )
    .await?;
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url())?;

    let mut headers = Vec::new();
    let mut beacon_roots = Vec::new();
    for nonce in 0..3u64 {
        let tx = TransactionRequest {
            nonce: Some(nonce),
            value: Some(U256::from(1)),
            to: Some(if nonce == 0 { TxKind::Create } else { Address::random().into() }),
            gas: Some(if nonce == 0 { 100_000 } else { 21_000 }),
            // Deploy a public contract returning TIMESTAMP and TIMESTAMPMS in the first block.
            input: TransactionInput::new(if nonce == 0 {
                bytes!("600d600c600039600d6000f3426000524b60205260406000f3")
            } else {
                Bytes::new()
            }),
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

        beacon_roots
            .push((block.header().timestamp_millis(), block.parent_beacon_block_root().unwrap()));
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

    // Build and import two more same-second blocks through the authenticated HTTP Engine API.
    // Unlike the harness's direct builder, this exercises FCU's parent timestamp validation.
    let engine_client = node.auth_server_handle().http_client();
    let tip = headers.last().unwrap();
    let tip_hash = node.block_hash(tip.number());
    let mut forkchoice = ForkchoiceState {
        head_block_hash: tip_hash,
        safe_block_hash: tip_hash,
        finalized_block_hash: tip_hash,
    };
    let mut last_part = tip.timestamp_millis_part;
    for part in [last_part + 1, last_part + 2] {
        let attributes = payload_attributes(BASE_SECONDS, part);
        let root = attributes.parent_beacon_block_root.unwrap();
        let response: ForkchoiceUpdated = engine_client
            .request("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, attributes])
            .await?;
        assert!(response.payload_status.is_valid());
        let payload_id = response.payload_id.expect("accepted attributes start a build");
        let built: SeismicExecutionPayloadEnvelopeV4 =
            engine_client.request("engine_getPayloadV4", rpc_params![payload_id]).await?;
        assert_eq!(built.execution_payload.timestamp(), BASE_SECONDS);
        assert_eq!(built.execution_payload.timestamp_millis_part, part);
        let status: PayloadStatus = engine_client
            .request(
                "engine_newPayloadV4",
                rpc_params![
                    built.execution_payload.clone(),
                    Vec::<B256>::new(),
                    root,
                    built.execution_requests.clone()
                ],
            )
            .await?;
        assert!(status.is_valid());
        forkchoice.head_block_hash = built.execution_payload.block_hash();
        let response: ForkchoiceUpdated = engine_client
            .request(
                "engine_forkchoiceUpdatedV3",
                rpc_params![forkchoice, None::<SeismicPayloadAttributes>],
            )
            .await?;
        assert!(response.payload_status.is_valid());
        last_part = part;
        beacon_roots.push((BASE_SECONDS * MILLIS_PER_SECOND + part, root));
    }

    // Equal and earlier full timestamps, including seconds regressions, cannot start builds.
    for (seconds, part, expected_code) in [
        (BASE_SECONDS, last_part, -38003),
        (BASE_SECONDS, last_part - 1, -38003),
        (BASE_SECONDS - 1, 999, -38003),
        (BASE_SECONDS, 1000, -32602),
    ] {
        let error = engine_client
            .request::<ForkchoiceUpdated, _>(
                "engine_forkchoiceUpdatedV3",
                rpc_params![forkchoice, payload_attributes(seconds, part)],
            )
            .await
            .unwrap_err();
        let jsonrpsee::core::ClientError::Call(error) = error else {
            panic!("expected Engine API rejection, got {error}")
        };
        assert_eq!(error.code(), expected_code, "{error}");
    }

    // Public RPC simulation at the tip exposes the canonical header's exact millisecond part.
    let tip: Value = client.request("eth_getBlockByNumber", rpc_params!["latest", false]).await?;
    assert_eq!(quantity(&tip["timestamp"]), BASE_SECONDS);
    assert_eq!(quantity(&tip["timestampMillisPart"]), last_part);
    let timestamp_contract = wallet.inner.address().create(0);
    let actual: Bytes = client
        .request(
            "eth_call",
            rpc_params![
                serde_json::json!({
                    "to": timestamp_contract,
                    "gas": "0x186a0",
                }),
                "latest"
            ],
        )
        .await?;
    let mut expected = U256::from(BASE_SECONDS).to_be_bytes::<32>().to_vec();
    expected.extend_from_slice(
        &U256::from(BASE_SECONDS * MILLIS_PER_SECOND + last_part).to_be_bytes::<32>(),
    );
    assert_eq!(actual.as_ref(), expected.as_slice());

    // All five distinct roots remain readable at the tip, rather than overwriting one
    // seconds-indexed entry. Queries use recombined milliseconds, as Summit must do.
    let beacon_contract = address!("000f3df6d732807ef1319fb7b8bb8522d0beac02");
    for (millis, expected) in beacon_roots {
        let actual: Bytes = client
            .request(
                "eth_call",
                rpc_params![
                    serde_json::json!({
                        "to": beacon_contract,
                        "input": Bytes::copy_from_slice(&U256::from(millis).to_be_bytes::<32>()),
                        "gas": "0x186a0",
                    }),
                    "latest"
                ],
            )
            .await?;
        assert_eq!(actual.as_ref(), expected.as_slice());
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
