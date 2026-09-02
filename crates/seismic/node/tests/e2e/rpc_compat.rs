//! Seismic RPC compatibility tests using test data from a Summit testnet.
//!
//! These tests import a chain produced by a Summit testnet (real consensus, chain ID 5124)
//! and verify RPC responses against captured `.io` test files.

use alloy_chains::Chain;
use alloy_genesis::Genesis;
use alloy_primitives::U256;
use eyre::Result;
use reth_chainspec::{make_genesis_header, ChainSpec};
use reth_e2e_test_utils::testsuite::{
    actions::{MakeCanonical, UpdateBlockInfo},
    setup::{NetworkSetup, Setup},
    TestBuilder,
};
use reth_primitives_traits::SealedHeader;
use reth_rpc_e2e_tests::rpc_compat::{InitializeFromExecutionApis, RunRpcCompatTests};
use reth_seismic_evm::SeismicEvmConfig;
use reth_seismic_node::{
    engine::SeismicEngineTypes, node::SeismicNode, purpose_keys::get_purpose_keys,
};
use std::{path::PathBuf, sync::Arc};
use tracing::info;

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_rpc_compat() -> Result<()> {
    reth_tracing::init_test_tracing();
    reth_seismic_node::utils::e2e::ensure_mock_purpose_keys();

    let test_data_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/testdata/rpc-compat");
    assert!(test_data_path.exists(), "Test data path missing: {}", test_data_path.display());
    info!("Using Seismic test data from: {}", test_data_path.display());

    let chain_rlp_path = test_data_path.join("chain.rlp");
    let fcu_json_path = test_data_path.join("headfcu.json");
    let genesis_path = test_data_path.join("genesis.json");

    assert!(chain_rlp_path.exists(), "chain.rlp not found");
    assert!(fcu_json_path.exists(), "headfcu.json not found");
    assert!(genesis_path.exists(), "genesis.json not found");

    // Load genesis from testdata so this test is decoupled from SEISMIC_DEV.
    let genesis_json =
        std::fs::read_to_string(&genesis_path).expect("failed to read genesis.json from testdata");
    let mut genesis: Genesis = serde_json::from_str(&genesis_json).expect("invalid genesis JSON");

    // Genesis JSON timestamps are in seconds, but when timestamp-in-seconds feature is disabled,
    // we store timestamps internally as milliseconds.
    #[cfg(not(feature = "timestamp-in-seconds"))]
    {
        genesis.timestamp *= 1000;
    }

    let hardforks = reth_seismic_forks::SEISMIC_DEV_HARDFORKS.clone();
    let chain_spec: Arc<ChainSpec> = ChainSpec {
        chain: Chain::from_id(genesis.config.chain_id),
        genesis_header: SealedHeader::seal_slow(make_genesis_header(&genesis, &hardforks)),
        genesis,
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks,
        ..Default::default()
    }
    .into();

    let setup = Setup::<SeismicEngineTypes>::default()
        .with_chain_spec(chain_spec.clone())
        .with_network(NetworkSetup::single_node());

    let test = TestBuilder::new()
        .with_setup_and_import(setup, chain_rlp_path)
        .with_action(UpdateBlockInfo::default())
        .with_action(
            InitializeFromExecutionApis::new().with_fcu_json(fcu_json_path.to_string_lossy()),
        )
        .with_action(MakeCanonical::new())
        .with_action(RunRpcCompatTests::new(
            vec!["eth_getLogs".to_string(), "eth_syncing".to_string()],
            test_data_path.to_string_lossy(),
        ));

    let evm_config = SeismicEvmConfig::new(chain_spec, get_purpose_keys());
    test.run_with_evm::<SeismicNode>(evm_config).await?;

    Ok(())
}
