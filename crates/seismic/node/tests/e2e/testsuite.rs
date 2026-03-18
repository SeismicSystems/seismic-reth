use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use eyre::Result;
use reth_e2e_test_utils::testsuite::{
    actions::AssertMineBlock,
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

#[tokio::test]
async fn test_testsuite_seismic_assert_mine_block() -> Result<()> {
    reth_tracing::init_test_tracing();

    // Initialize mock purpose keys — required before the Seismic node can start.
    // In production this happens in main.rs after booting the enclave.
    let _ = std::panic::catch_unwind(|| {
        init_purpose_keys(GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        });
    });

    let setup = Setup::default()
        .with_chain_spec(SEISMIC_MAINNET.clone())
        .with_network(NetworkSetup::single_node());

    let test = TestBuilder::new().with_setup(setup).with_action(AssertMineBlock::<
        SeismicEngineTypes,
    >::new(
        0,
        vec![],
        None,
        // TODO: refactor once we have actions to generate payload attributes.
        PayloadAttributes {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            prev_randao: B256::random(),
            suggested_fee_recipient: Address::random(),
            withdrawals: Some(vec![]),
            parent_beacon_block_root: Some(B256::ZERO),
        },
    ));

    test.run::<SeismicNode>().await?;

    Ok(())
}
