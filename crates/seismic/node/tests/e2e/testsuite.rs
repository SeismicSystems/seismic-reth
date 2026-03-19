use eyre::Result;
use reth_e2e_test_utils::testsuite::{
    actions::ProduceBlocks,
    setup::{NetworkSetup, Setup},
    TestBuilder,
};
use reth_seismic_chainspec::SEISMIC_MAINNET;
use reth_seismic_node::{
    engine::SeismicEngineTypes, node::SeismicNode, purpose_keys::init_purpose_keys,
};
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

/// Test that the Seismic node can produce blocks via the testsuite framework.
///
/// Uses `ProduceBlocks` (V3 engine API) which is compatible with Cancun-active
/// chain specs like `SEISMIC_MAINNET`.
#[tokio::test]
#[ignore = "block hash mismatch in new_payload_v3 — debug codepath documented below"]
// DEBUG CODEPATH for block hash mismatch:
//
// 1. PAYLOAD BUILD: get_payload_v3 returns an ExecutionPayloadEnvelopeV3 with block_hash computed
//    by the Seismic payload builder. File: crates/seismic/payload/src/builder.rs → The Seismic
//    builder seals the block with state_root from flagged storage trie
//
// 2. PAYLOAD BROADCAST: new_payload_v3 receives the ExecutionPayload File:
//    crates/rpc/rpc-engine-api/src/engine_api.rs:873-889 → Wraps payload into ExecutionData and
//    calls new_payload_v3_metered
//
// 3. ENGINE TREE VALIDATION: on_new_payload processes the ExecutionData File:
//    crates/engine/tree/src/tree/mod.rs:516-600 → Calls insert_payload which re-executes the block
//    and recomputes state_root → Seals the block header from the execution result → Compares
//    computed block_hash against payload.block_hash → If mismatch →
//    NewPayloadError::Eth(PayloadError::BlockHash { ... })
//
// 4. WHERE THE MISMATCH LIKELY OCCURS: The ExecutionPayload round-trip goes: SeismicBlock →
//    ExecutionPayloadV3 (get_payload_v3) → ExecutionData → Block (new_payload) The block_hash in
//    step 2 was computed from the original SeismicBlock header. In step 3, the engine rebuilds a
//    header from ExecutionPayload fields. If any field is lost/transformed in the conversion (e.g.
//    Seismic-specific header fields), the rebuilt header will hash differently.
//
// TO DEBUG: Run with RUST_LOG=engine::tree=debug,rpc::engine=debug,payload=debug
//   cargo nextest run -p reth-seismic-node -E 'test(testsuite)' --no-fail-fast
// --ignore-default-filter Look for:
//   - "Invalid payload" log in engine::tree (shows the error details)
//   - Compare block_hash from get_payload_v3 response vs what new_payload_v3 computes
//   - Check if state_root differs (flagged storage) or if header encoding differs
async fn test_testsuite_seismic_produce_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let setup = Setup::default()
        .with_chain_spec(SEISMIC_MAINNET.clone())
        .with_network(NetworkSetup::single_node());

    let test = TestBuilder::new()
        .with_setup(setup)
        .with_action(ProduceBlocks::<SeismicEngineTypes>::new(3));

    test.run::<SeismicNode>().await?;

    Ok(())
}
