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
