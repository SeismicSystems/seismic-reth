//! RPC simulations must never publish speculative rotations to the live keyring.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use alloy_primitives::{Bytes, TxKind, U256};
use alloy_rpc_types::Block;
use alloy_sol_types::{sol, SolCall};
use jsonrpsee::http_client::HttpClientBuilder;
use reth_chainspec::make_genesis_header;
use reth_e2e_test_utils::{setup_engine, wallet::Wallet};
use reth_primitives_traits::SealedHeader;
use reth_provider::StateProviderFactory;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_keys::registry::{ADMIN_SLOT, KEY_ROTATION_REGISTRY, ROTATIONS_LEN_SLOT};
use reth_seismic_node::{
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, seismic_payload_attributes},
};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use reth_seismic_test_utils::get_signed_seismic_call_bytes;
use seismic_alloy_rpc_types::{SeismicCallRequest, SimBlock, SimulatePayload};
use std::{sync::Arc, time::Duration};

sol! {
    function announceRotation(uint64 activationBlock);
}

/// Exercise the real HTTP handler, registry bytecode, and multi-block simulation.
/// The genesis fixture makes the test wallet the registry admin; it does not use
/// forbidden RPC storage overrides or impersonate an unsigned sender.
#[tokio::test(flavor = "multi_thread")]
async fn simulate_v1_keeps_rotation_local_on_success_and_error() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();
    let mut spec = SEISMIC_DEV.as_ref().clone();
    let admin = Wallet::default().inner.address();
    spec.genesis
        .alloc
        .get_mut(&KEY_ROTATION_REGISTRY)
        .unwrap()
        .storage
        .as_mut()
        .unwrap()
        .insert(ADMIN_SLOT, admin.into_word());
    spec.genesis_header =
        SealedHeader::seal_slow(make_genesis_header(&spec.genesis, &spec.hardforks));

    let (mut nodes, _tasks, wallet) = tokio::spawn(setup_engine::<SeismicNode>(
        1,
        Arc::new(spec),
        false,
        Default::default(),
        seismic_payload_attributes,
    ))
    .await??;
    let node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url())?;
    let genesis_hash = node.block_hash(0);
    let live = node.inner.evm_config.executor_factory.keyring.clone();
    let before = (live.canonical_view(), live.requested_epochs());

    // The first simulated block is 1; dev genesis requires a 32-block delay.
    let activation = 33;
    let announcement = get_signed_seismic_call_bytes(
        &wallet.inner,
        0,
        TxKind::Call(KEY_ROTATION_REGISTRY),
        wallet.chain_id,
        Bytes::from(announceRotationCall { activationBlock: activation }.abi_encode()),
        genesis_hash,
    )
    .await;
    let first = SimBlock {
        block_overrides: None,
        state_overrides: None,
        calls: vec![SeismicCallRequest::Bytes(announcement)],
    };
    let empty = SimBlock { block_overrides: None, state_overrides: None, calls: vec![] };
    let payload = SimulatePayload {
        block_state_calls: vec![first.clone(), empty.clone()],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };

    // Block 2's pre-execution initialization reads the registry written in block 1.
    // Repeat the request to also check that a finished request leaves no residue.
    for _ in 0..2 {
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            EthApiOverrideClient::<Block>::simulate_v1(&client, payload.clone(), Some(0.into())),
        )
        .await??;
        assert_eq!(result.len(), 2);
        assert!(
            result.first().unwrap().calls.first().unwrap().status,
            "the authorized announcement must execute successfully in the simulation"
        );
        assert_eq!((live.canonical_view(), live.requested_epochs()), before);
        assert_eq!(live.epoch_for_block(activation), 0);
    }

    // The private parent overlays retain the announcement across simulated
    // blocks. At activation, missing epoch-1 keys must fail the request without
    // enqueueing a live custodian fetch or publishing canonical metadata.
    let mut blocks = vec![first];
    blocks.extend(std::iter::repeat_n(empty, (activation - 1) as usize));
    let payload = SimulatePayload { block_state_calls: blocks, ..payload };
    let err = tokio::time::timeout(
        Duration::from_secs(30),
        EthApiOverrideClient::<Block>::simulate_v1(&client, payload, Some(0.into())),
    )
    .await?
    .expect_err("unfetched simulated epoch must fail at activation");
    assert!(err.to_string().contains("purpose keys"), "unexpected error: {err}");
    assert_eq!((live.canonical_view(), live.requested_epochs()), before);
    assert!(live.keys_for_epoch(1).is_none());

    // Nor did the simulation alter the real registry's rotations.length slot.
    let length = node
        .inner
        .provider
        .latest()?
        .storage(KEY_ROTATION_REGISTRY, ROTATIONS_LEN_SLOT)?
        .unwrap_or_default()
        .value;
    assert_eq!(length, U256::ZERO);
    Ok(())
}
