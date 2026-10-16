//! Sub-second block timestamps: the `extraData` prefix, Engine API round trip, consensus ordering
//! and the public RPC shape (stock headers, stock hashes).

use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::{address, bytes, Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV4, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes,
    PayloadStatus,
};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_engine_primitives::PayloadValidator;
use reth_payload_primitives::PayloadTypes;
use reth_seismic_engine_primitives::{
    extra_data::{builder_extra_data, decode_timestamp_millis_part},
    SeismicPayloadAttributes, SeismicPayloadBuilderAttributes, MILLIS_PER_SECOND,
};
use reth_seismic_node::{
    consensus::validate_against_parent_timestamp_millis,
    engine::{SeismicEngineTypes, SeismicEngineValidator},
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, test_chain_spec},
};
use reth_seismic_primitives::SeismicBlockHeader;
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

        // The built header carries the attributes' split timestamp: seconds in `timestamp`,
        // the part as the `extraData` prefix.
        let header = block.header();
        assert_eq!(header.timestamp(), BASE_SECONDS, "seconds part");
        let part = header.try_timestamp_millis_part()?;
        assert!(part < MILLIS_PER_SECOND);
        assert_eq!(header.timestamp_millis(), BASE_SECONDS * MILLIS_PER_SECOND + part);
        // The builder tag survives verbatim behind the prefix (the harness runs the default
        // `--builder.extradata`).
        assert_eq!(
            builder_extra_data(header.extra_data()),
            reth_node_core::version::default_extra_data_bytes().as_ref()
        );

        // Engine API round trip: the stock payload carries the part in `extraData` and rebuilds
        // the same block/hash.
        let execution_data = SeismicEngineTypes::block_to_payload(block.clone());
        assert_eq!(
            decode_timestamp_millis_part(&execution_data.payload.as_v1().extra_data),
            Ok(part)
        );
        assert_eq!(execution_data.payload.timestamp(), BASE_SECONDS);
        let validator = SeismicEngineValidator::new(chain_spec.clone());
        let rebuilt = PayloadValidator::<SeismicEngineTypes>::ensure_well_formed_payload(
            &validator,
            execution_data,
        )?;
        assert_eq!(rebuilt.hash(), block.hash());
        assert_eq!(rebuilt.header(), header);

        // Public RPC: a stock header. `timestamp` is seconds, there is no extra field, and the
        // hash is the standard hash of the standard fields, so stock tooling can verify it.
        let rpc_block: Value = client
            .request("eth_getBlockByNumber", rpc_params![format!("{:#x}", block.number()), false])
            .await?;
        assert_eq!(quantity(&rpc_block["timestamp"]), BASE_SECONDS);
        assert!(rpc_block.get("timestampMillisPart").is_none());
        let extra_data: Bytes = rpc_block["extraData"].as_str().unwrap().parse()?;
        assert_eq!(decode_timestamp_millis_part(&extra_data), Ok(part));
        let rpc_header: alloy_rpc_types_eth::Header<Header> =
            serde_json::from_value(rpc_block.clone())?;
        assert_eq!(rpc_header.hash, block.hash());
        assert_eq!(rpc_header.inner.hash_slow(), block.hash(), "stock header hash");

        beacon_roots.push((header.timestamp_millis(), block.parent_beacon_block_root().unwrap()));
        headers.push(header.clone());
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
    let mut last_part = tip.timestamp_millis_part();
    for part in [last_part + 1, last_part + 2] {
        let attributes = payload_attributes(BASE_SECONDS, part);
        let root = attributes.parent_beacon_block_root.unwrap();
        let response: ForkchoiceUpdated = engine_client
            .request("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, attributes])
            .await?;
        assert!(response.payload_status.is_valid());
        let payload_id = response.payload_id.expect("accepted attributes start a build");
        let built: ExecutionPayloadEnvelopeV4 =
            engine_client.request("engine_getPayloadV4", rpc_params![payload_id]).await?;
        let built_payload = &built.execution_payload.payload_inner.payload_inner;
        assert_eq!(built_payload.timestamp, BASE_SECONDS);
        assert_eq!(decode_timestamp_millis_part(&built_payload.extra_data), Ok(part));
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
        forkchoice.head_block_hash = built_payload.block_hash;
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

    // Every advertised `engine_getPayloadV*` either serves the built payload or rejects it with
    // `-38005 Unsupported fork`; a version the node advertises must never answer `-38001 Unknown
    // payload` for a payload id that exists. Which versions serve follows reth's fork validation
    // at the payload's timestamp: V1 is never fork-validated upstream, V2 only pre-Cancun, V3
    // from Cancun, V4 from Prague, V5 from Osaka (lower bounds only).
    {
        use reth_chainspec::EthereumHardforks;
        let capabilities: Vec<String> = engine_client
            .request("engine_exchangeCapabilities", rpc_params![Vec::<String>::new()])
            .await?;
        let advertised: Vec<&str> = capabilities
            .iter()
            .map(String::as_str)
            .filter(|c| c.starts_with("engine_getPayloadV"))
            .collect();
        assert!(advertised.contains(&"engine_getPayloadV4"), "{capabilities:?}");
        assert!(advertised.contains(&"engine_getPayloadV5"), "{capabilities:?}");
        let serves = |method: &str| match method {
            "engine_getPayloadV1" => true,
            "engine_getPayloadV2" => !chain_spec.is_cancun_active_at_timestamp(BASE_SECONDS),
            "engine_getPayloadV3" => chain_spec.is_cancun_active_at_timestamp(BASE_SECONDS),
            "engine_getPayloadV4" => chain_spec.is_prague_active_at_timestamp(BASE_SECONDS),
            "engine_getPayloadV5" => chain_spec.is_osaka_active_at_timestamp(BASE_SECONDS),
            other => panic!("unexpected capability {other}"),
        };

        let response: ForkchoiceUpdated = engine_client
            .request(
                "engine_forkchoiceUpdatedV3",
                rpc_params![forkchoice, payload_attributes(BASE_SECONDS, last_part + 1)],
            )
            .await?;
        let payload_id = response.payload_id.expect("accepted attributes start a build");
        let mut served = Vec::new();
        for method in advertised {
            let result: Result<Value, _> =
                engine_client.request(method, rpc_params![payload_id]).await;
            match result {
                Ok(envelope) => {
                    assert!(serves(method), "{method} served a payload outside its fork window");
                    // V1 returns the bare payload; V2+ wrap it in an envelope.
                    let payload = envelope.get("executionPayload").unwrap_or(&envelope);
                    let hash: B256 = payload["blockHash"].as_str().unwrap().parse()?;
                    served.push(hash);
                }
                Err(jsonrpsee::core::ClientError::Call(error)) => {
                    assert_eq!(error.code(), -38005, "{method}: {error}");
                    assert!(!serves(method), "{method} rejected a payload it should serve");
                }
                Err(error) => panic!("{method}: {error}"),
            }
        }
        assert!(!served.is_empty());
        assert!(served.iter().all(|h| h == &served[0]), "all serving versions agree");
    }

    // A payload whose `extraData` breaks the layout is rejected by consensus even though it is
    // a well-formed stock block: strip the prefix and re-seal.
    {
        let mut tampered = built_payload_block(&engine_client, &forkchoice, last_part + 1).await?;
        let header = &mut tampered.0.payload_inner.payload_inner;
        header.extra_data = Bytes::new();
        let mut consensus_header: Header = tampered.1.clone();
        consensus_header.extra_data = Bytes::new();
        header.block_hash = consensus_header.hash_slow();
        let status: PayloadStatus = engine_client
            .request(
                "engine_newPayloadV4",
                rpc_params![tampered.0, Vec::<B256>::new(), tampered.2, tampered.3],
            )
            .await?;
        assert!(status.is_invalid(), "{status:?}");
        assert!(status.status.to_string().contains("extraData is 0 bytes"), "{:?}", status.status);
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
    let tip_extra_data: Bytes = tip["extraData"].as_str().unwrap().parse()?;
    assert_eq!(decode_timestamp_millis_part(&tip_extra_data), Ok(last_part));
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

    // The genesis block carries a zero part prefix, and the chain spec's hash is its stock hash.
    let genesis: Value = client.request("eth_getBlockByNumber", rpc_params!["0x0", false]).await?;
    let genesis_extra_data: Bytes = genesis["extraData"].as_str().unwrap().parse()?;
    assert_eq!(decode_timestamp_millis_part(&genesis_extra_data), Ok(0));
    assert_eq!(
        genesis["hash"].as_str().unwrap().parse::<alloy_primitives::B256>()?,
        chain_spec.genesis_hash()
    );

    Ok(())
}

/// Builds a payload on top of `forkchoice` through the Engine API without importing it, returning
/// the stock payload, its header, the parent beacon root and the execution requests.
async fn built_payload_block<C: ClientT + Sync>(
    engine_client: &C,
    forkchoice: &ForkchoiceState,
    part: u64,
) -> eyre::Result<(
    alloy_rpc_types_engine::ExecutionPayloadV3,
    Header,
    B256,
    alloy_eips::eip7685::Requests,
)> {
    let attributes = payload_attributes(BASE_SECONDS, part);
    let root = attributes.parent_beacon_block_root.unwrap();
    let response: ForkchoiceUpdated = engine_client
        .request("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, attributes])
        .await?;
    let payload_id = response.payload_id.expect("accepted attributes start a build");
    let built: ExecutionPayloadEnvelopeV4 =
        engine_client.request("engine_getPayloadV4", rpc_params![payload_id]).await?;
    let sidecar = alloy_rpc_types_engine::ExecutionPayloadSidecar::v4(
        alloy_rpc_types_engine::CancunPayloadFields {
            parent_beacon_block_root: root,
            versioned_hashes: vec![],
        },
        alloy_rpc_types_engine::PraguePayloadFields {
            requests: alloy_eips::eip7685::RequestsOrHash::Requests(
                built.execution_requests.clone(),
            ),
        },
    );
    let ExecutionPayloadEnvelopeV4 { envelope_inner, execution_requests } = built;
    let payload = envelope_inner.execution_payload;
    let block: alloy_consensus::Block<seismic_alloy_consensus::SeismicTxEnvelope> =
        alloy_rpc_types_engine::ExecutionPayload::V3(payload.clone())
            .try_into_block_with_sidecar(&sidecar)?;
    Ok((payload, block.header, root, execution_requests))
}

/// On an explicitly Osaka-enabled chain `engine_getPayloadV5` must serve the built payload
/// (it is advertised and passes fork validation), with the same block as V4.
#[tokio::test(flavor = "multi_thread")]
async fn get_payload_v5_serves_on_an_osaka_chain() -> eyre::Result<()> {
    use alloy_rpc_types_engine::ExecutionPayloadEnvelopeV5;
    use reth_chainspec::{EthereumHardfork, ForkCondition};

    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let mut chain_spec = (*test_chain_spec()).clone();
    chain_spec.hardforks.insert(EthereumHardfork::Osaka, ForkCondition::Timestamp(0));
    let chain_spec = std::sync::Arc::new(chain_spec);
    let (mut nodes, _tasks, _wallet) = reth_e2e_test_utils::setup_engine::<SeismicNode>(
        1,
        chain_spec.clone(),
        false,
        Default::default(),
        |timestamp| {
            SeismicPayloadBuilderAttributes::new(
                B256::ZERO,
                payload_attributes(BASE_SECONDS, (timestamp % 100) * 7),
            )
            .unwrap()
        },
    )
    .await?;
    let node = nodes.pop().unwrap();
    let engine_client = node.auth_server_handle().http_client();

    let genesis_hash = chain_spec.genesis_hash();
    let forkchoice = ForkchoiceState {
        head_block_hash: genesis_hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };
    let response: ForkchoiceUpdated = engine_client
        .request(
            "engine_forkchoiceUpdatedV3",
            rpc_params![forkchoice, payload_attributes(BASE_SECONDS, 1)],
        )
        .await?;
    let payload_id = response.payload_id.expect("accepted attributes start a build");

    let v4: ExecutionPayloadEnvelopeV4 =
        engine_client.request("engine_getPayloadV4", rpc_params![payload_id]).await?;
    let v5: ExecutionPayloadEnvelopeV5 =
        engine_client.request("engine_getPayloadV5", rpc_params![payload_id]).await?;
    assert_eq!(v5.execution_payload, v4.execution_payload);
    assert_eq!(v5.execution_requests, v4.execution_requests);
    assert!(v5.blobs_bundle.blobs.is_empty());
    assert_eq!(
        decode_timestamp_millis_part(&v5.execution_payload.payload_inner.payload_inner.extra_data),
        Ok(1)
    );
    Ok(())
}
