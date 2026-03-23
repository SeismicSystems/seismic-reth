//! RPC compatibility tests using execution-apis test data.
//!
//! # Current Status
//!
//! The main test `test_local_rpc_tests_compat` is **ignored** because the test data
//! (chain.rlp, genesis.json, headfcu.json) was generated from an upstream Ethereum
//! execution-apis test suite that uses standard (non-flagged) storage. Seismic's trie
//! implementation hashes storage values as `FlaggedStorage` (a `U256` value plus a
//! one-byte privacy flag), which produces different state roots than standard Ethereum.
//! When the node imports blocks from chain.rlp and recomputes state roots, the computed
//! roots will not match the block headers, causing the import to fail.
//!
//! # What Needs to Change to Re-enable
//!
//! New test data must be generated from a running Seismic node so that the block headers
//! contain state roots computed with flagged storage. Steps:
//!
//! 1. Run a local Seismic devnet (e.g. `cargo run -- node --dev --dev.block-time 1s`)
//! 2. Deploy contracts and submit transactions that exercise storage (SSTORE/SLOAD) and emit logs
//!    to cover the `eth_getLogs` test cases
//! 3. Export the chain using `reth db export-chain <output.rlp> --to <block_number>`
//! 4. Capture the genesis.json from the devnet configuration
//! 5. Record the head forkchoice state as headfcu.json
//! 6. Write new `.io` test case files with the correct expected RPC responses
//! 7. Replace the files in `testdata/rpc-compat/` and remove the `#[ignore]` annotation

use eyre::Result;
use reth_chainspec::ChainSpec;
use reth_e2e_test_utils::testsuite::{
    actions::{MakeCanonical, UpdateBlockInfo},
    setup::{NetworkSetup, Setup},
    TestBuilder,
};
use reth_node_ethereum::{EthEngineTypes, EthereumNode};
use reth_rpc_e2e_tests::rpc_compat::{InitializeFromExecutionApis, RunRpcCompatTests};
use seismic_alloy_genesis::Genesis;
use std::{env, path::PathBuf, sync::Arc};
use tracing::{debug, info};

/// Test repo-local RPC method compatibility with execution-apis test data.
///
/// This test is currently ignored because the bundled test data contains blocks whose
/// state roots were computed using standard Ethereum storage hashing. Seismic uses
/// `FlaggedStorage` in its trie cursors (see `crates/trie/trie/src/hashed_cursor/mod.rs`),
/// which prepends a privacy flag byte to each storage value before hashing. This means
/// state roots produced by a Seismic node will differ from those in the test data, and
/// block import will fail with a state root mismatch.
///
/// To re-enable this test, regenerate the test data from a Seismic devnet. See the
/// module-level documentation for step-by-step instructions.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Test data has state roots from standard Ethereum storage hashing; Seismic uses FlaggedStorage which produces different roots. Regenerate test data from a Seismic devnet to fix."]
async fn test_local_rpc_tests_compat() -> Result<()> {
    reth_tracing::init_test_tracing();

    // Use local test data
    let test_data_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/rpc-compat");

    assert!(test_data_path.exists(), "Test data path does not exist: {}", test_data_path.display());

    info!("Using test data from: {}", test_data_path.display());

    // Paths to test files
    let chain_rlp_path = test_data_path.join("chain.rlp");
    let fcu_json_path = test_data_path.join("headfcu.json");
    let genesis_path = test_data_path.join("genesis.json");

    // Verify required files exist
    if !chain_rlp_path.exists() {
        return Err(eyre::eyre!("chain.rlp not found at {}", chain_rlp_path.display()));
    }
    if !fcu_json_path.exists() {
        return Err(eyre::eyre!("headfcu.json not found at {}", fcu_json_path.display()));
    }
    if !genesis_path.exists() {
        return Err(eyre::eyre!("genesis.json not found at {}", genesis_path.display()));
    }

    // Load genesis from test data
    let genesis_json = std::fs::read_to_string(&genesis_path)?;

    // Parse the Genesis struct from JSON and convert it to ChainSpec
    // This properly handles all the hardfork configuration from the config section
    let genesis: Genesis = serde_json::from_str(&genesis_json)?;
    let chain_spec: ChainSpec = genesis.into();
    let chain_spec = Arc::new(chain_spec);

    // Create test setup with imported chain
    let setup = Setup::<EthEngineTypes>::default()
        .with_chain_spec(chain_spec)
        .with_network(NetworkSetup::single_node());

    // Build and run the test
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

    test.run::<EthereumNode>().await?;

    Ok(())
}

/// Test RPC method compatibility with execution-apis test data from environment variable
///
/// This test:
/// 1. Reads test data path from `EXECUTION_APIS_TEST_PATH` environment variable
/// 2. Auto-discovers all RPC method directories (starting with `eth_`)
/// 3. Initializes a node with chain data from that directory (chain.rlp)
/// 4. Applies the forkchoice state from headfcu.json
/// 5. Runs all discovered RPC test cases individually (each test file reported separately)
#[tokio::test(flavor = "multi_thread")]
async fn test_execution_apis_compat() -> Result<()> {
    reth_tracing::init_test_tracing();

    // Get test data path from environment variable
    let test_data_path = match env::var("EXECUTION_APIS_TEST_PATH") {
        Ok(path) => path,
        Err(_) => {
            info!("SKIPPING: EXECUTION_APIS_TEST_PATH environment variable not set. Please set it to the path of execution-apis/tests directory to run this test.");
            return Ok(());
        }
    };

    let test_data_path = PathBuf::from(test_data_path);

    if !test_data_path.exists() {
        return Err(eyre::eyre!("Test data path does not exist: {}", test_data_path.display()));
    }

    info!("Using execution-apis test data from: {}", test_data_path.display());

    // Auto-discover RPC method directories
    let mut rpc_methods = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&test_data_path) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                // Search for an underscore to get all namespaced directories
                if entry.path().is_dir() && name.contains('_') {
                    rpc_methods.push(name.to_string());
                }
            }
        }
    }

    if rpc_methods.is_empty() {
        return Err(eyre::eyre!(
            "No RPC method directories (containing a '_' indicating namespacing) found in {}",
            test_data_path.display()
        ));
    }

    rpc_methods.sort();
    debug!("Found RPC method test directories: {:?}", rpc_methods);

    // Paths to chain config files
    let chain_rlp_path = test_data_path.join("chain.rlp");
    let genesis_path = test_data_path.join("genesis.json");
    let fcu_json_path = test_data_path.join("headfcu.json");

    // Verify required files exist
    if !chain_rlp_path.exists() {
        return Err(eyre::eyre!("chain.rlp not found at {}", chain_rlp_path.display()));
    }
    if !fcu_json_path.exists() {
        return Err(eyre::eyre!("headfcu.json not found at {}", fcu_json_path.display()));
    }
    if !genesis_path.exists() {
        return Err(eyre::eyre!("genesis.json not found at {}", genesis_path.display()));
    }

    // Load genesis from test data
    let genesis_json = std::fs::read_to_string(&genesis_path)?;
    let genesis: Genesis = serde_json::from_str(&genesis_json)?;
    let chain_spec: ChainSpec = genesis.into();
    let chain_spec = Arc::new(chain_spec);

    // Create test setup with imported chain
    let setup = Setup::<EthEngineTypes>::default()
        .with_chain_spec(chain_spec)
        .with_network(NetworkSetup::single_node());

    // Build and run the test with all discovered methods
    let test = TestBuilder::new()
        .with_setup_and_import(setup, chain_rlp_path)
        .with_action(UpdateBlockInfo::default())
        .with_action(
            InitializeFromExecutionApis::new().with_fcu_json(fcu_json_path.to_string_lossy()),
        )
        .with_action(MakeCanonical::new())
        .with_action(RunRpcCompatTests::new(rpc_methods, test_data_path.to_string_lossy()));

    test.run::<EthereumNode>().await?;

    Ok(())
}

/// Validates that all RPC compatibility test data files are present and well-formed.
///
/// This test runs even while `test_local_rpc_tests_compat` is ignored, ensuring that
/// the test data directory stays structurally valid so re-enabling the main test only
/// requires regenerating data with correct (flagged-storage) state roots.
#[test]
fn test_rpc_compat_test_data_is_well_formed() {
    let test_data_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/rpc-compat");

    // Required top-level files exist
    assert!(test_data_path.exists(), "testdata/rpc-compat directory missing");
    assert!(test_data_path.join("chain.rlp").exists(), "chain.rlp missing");
    assert!(test_data_path.join("genesis.json").exists(), "genesis.json missing");
    assert!(test_data_path.join("headfcu.json").exists(), "headfcu.json missing");

    // chain.rlp is non-empty
    let chain_rlp_meta =
        std::fs::metadata(test_data_path.join("chain.rlp")).expect("failed to stat chain.rlp");
    assert!(chain_rlp_meta.len() > 0, "chain.rlp is empty");

    // genesis.json parses into a valid Genesis / ChainSpec
    let genesis_json =
        std::fs::read_to_string(test_data_path.join("genesis.json")).expect("read genesis.json");
    let genesis: Genesis =
        serde_json::from_str(&genesis_json).expect("genesis.json is not valid Genesis JSON");
    let chain_spec: ChainSpec = genesis.into();
    assert!(chain_spec.chain().id() > 0, "chain ID should be non-zero");

    // headfcu.json has valid structure
    let fcu_json =
        std::fs::read_to_string(test_data_path.join("headfcu.json")).expect("read headfcu.json");
    let fcu: serde_json::Value =
        serde_json::from_str(&fcu_json).expect("headfcu.json is not valid JSON");
    assert_eq!(
        fcu.get("method").and_then(|v| v.as_str()),
        Some("engine_forkchoiceUpdatedV3"),
        "headfcu.json must use engine_forkchoiceUpdatedV3"
    );
    let params = fcu.get("params").expect("headfcu.json missing params");
    assert!(params.is_array(), "headfcu.json params must be an array");
    let fcu_state = params.as_array().unwrap().first().expect("headfcu.json params[0] missing");
    assert!(
        fcu_state.get("headBlockHash").is_some(),
        "headfcu.json params[0] missing headBlockHash"
    );
    assert!(
        fcu_state.get("safeBlockHash").is_some(),
        "headfcu.json params[0] missing safeBlockHash"
    );
    assert!(
        fcu_state.get("finalizedBlockHash").is_some(),
        "headfcu.json params[0] missing finalizedBlockHash"
    );

    // At least one RPC method directory with .io test files
    let mut method_dirs: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&test_data_path).expect("read testdata dir") {
        let entry = entry.expect("read dir entry");
        if entry.path().is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                if name.contains('_') {
                    method_dirs.push(name.to_string());
                }
            }
        }
    }
    assert!(!method_dirs.is_empty(), "no RPC method directories (with '_') found");

    // Each method directory contains at least one well-formed .io file
    for method in &method_dirs {
        let method_dir = test_data_path.join(method);
        let mut io_count = 0u32;

        for entry in std::fs::read_dir(&method_dir)
            .unwrap_or_else(|e| panic!("failed to read {method} dir: {e}"))
        {
            let entry = entry.expect("read entry");
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("io") {
                continue;
            }
            io_count += 1;

            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

            // Must contain >> (request) and << (response) markers
            assert!(content.contains(">> "), "{}: missing request marker (>>)", path.display());
            assert!(content.contains("<< "), "{}: missing response marker (<<)", path.display());

            // Extract and validate JSON in request and response lines
            for line in content.lines() {
                let line = line.trim();
                if let Some(json_str) = line.strip_prefix(">>") {
                    let json_str = json_str.trim();
                    let val: serde_json::Value =
                        serde_json::from_str(json_str).unwrap_or_else(|e| {
                            panic!("{}: invalid request JSON: {e}", path.display())
                        });
                    assert!(
                        val.get("method").is_some(),
                        "{}: request missing 'method' field",
                        path.display()
                    );
                } else if let Some(json_str) = line.strip_prefix("<<") {
                    let json_str = json_str.trim();
                    let val: serde_json::Value =
                        serde_json::from_str(json_str).unwrap_or_else(|e| {
                            panic!("{}: invalid response JSON: {e}", path.display())
                        });
                    // Response must have either "result" or "error"
                    assert!(
                        val.get("result").is_some() || val.get("error").is_some(),
                        "{}: response missing both 'result' and 'error' fields",
                        path.display()
                    );
                }
            }
        }
        assert!(io_count > 0, "{method}/ directory contains no .io test files");
    }
}
