//! Tests that Seismic hardfork configuration (Mercury) is correctly reported via RPC.
//!
//! This is the Seismic equivalent of `test_eth_config` in `crates/ethereum/node/tests/e2e/rpc.rs`,
//! which was disabled with `#[ignore = "We disabled fork activations"]`.
//!
//! Instead of testing fork scheduling (past/current/next at different timestamps), we verify
//! that the Seismic chain spec with Mercury hardfork active at genesis is correctly reflected
//! in the `eth_config` RPC response.

use alloy_eips::eip7910::EthConfig;
use alloy_primitives::{Address, B256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_seismic_evm::PurposeKeys;
use reth_chainspec::{EthChainSpec, Hardforks, Head};
use reth_e2e_test_utils::setup;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_node::{node::SeismicNode, purpose_keys::init_purpose_keys};
use std::sync::Once;

/// Ensure mock purpose keys are initialized exactly once per test binary.
static INIT_KEYS: Once = Once::new();
fn ensure_mock_purpose_keys() {
    INIT_KEYS.call_once(|| {
        init_purpose_keys(PurposeKeys::well_known());
    });
}

/// Helper function to create a new eth payload attributes
fn eth_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Validates that the Mercury hardfork is correctly configured and reported via `eth_config` RPC.
///
/// This test:
/// 1. Starts a Seismic node with the dev chain spec (all forks including Mercury at timestamp 0)
/// 2. Advances a block so the node has chain state
/// 3. Calls `eth_config` RPC ([EIP-7910](https://eips.ethereum.org/EIPS/eip-7910)) and verifies the
///    response
/// 4. Asserts that the current fork `activation_time` is 0 (Mercury active at genesis)
/// 5. Asserts that the `chain_id` matches the Seismic dev chain
/// 6. Asserts there is no next fork scheduled
#[tokio::test(flavor = "multi_thread")]
async fn test_mercury_hardfork_config() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let chain_spec = SEISMIC_DEV.clone();

    let (mut nodes, _tasks, wallet) =
        setup::<SeismicNode>(1, chain_spec.clone(), false, eth_payload_attributes).await?;
    let mut node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    // Send a transaction and advance a block so the node has chain state beyond genesis
    let _ = provider.send_transaction(TransactionRequest::default().to(Address::ZERO)).await?;
    node.advance_block().await?;

    // Get the latest block timestamp for fork_id verification
    let latest_block = provider.get_block_number().await?;
    let latest_timestamp = provider
        .get_block_by_number(latest_block.into())
        .await?
        .expect("latest block should exist")
        .header
        .timestamp;

    // Query the eth_config RPC endpoint (EIP-7910)
    let config: EthConfig = provider.client().request_noparams::<EthConfig>("eth_config").await?;

    // All Seismic forks (including Mercury) are activated at timestamp 0, so the current fork
    // should have activation_time = 0.
    assert_eq!(
        config.current.activation_time, 0,
        "Mercury hardfork should be active at timestamp 0"
    );

    // The chain_id in the config should match the Seismic dev chain id
    assert_eq!(
        config.current.chain_id,
        chain_spec.chain().id(),
        "chain_id should match Seismic dev chain"
    );

    // The fork_id should be non-empty and match the Seismic dev chain's fork hash,
    // which is derived from the genesis hash and all fork block/timestamp activations.
    // This is a stronger check than just activation_time — it proves the full fork
    // schedule is Seismic-specific.
    assert!(!config.current.fork_id.is_empty(), "fork_id should be set");

    // Verify the fork_id matches what we compute from the chain spec directly.
    // The fork_id is derived from genesis hash + all fork activations, so this proves
    // the node is running with the correct Seismic fork schedule.
    let fork_id = chain_spec.fork_id(&Head { timestamp: latest_timestamp, ..Default::default() });
    let expected_fork_hash = fork_id.hash.0;
    let reported_fork_hash = config.current.fork_id.get(..4);
    assert_eq!(
        reported_fork_hash,
        Some(expected_fork_hash.as_slice()),
        "fork_id should match the Seismic dev chain fork hash"
    );

    // Since all forks are at timestamp 0, there should be no next fork scheduled
    assert!(config.next.is_none(), "no next fork should be scheduled");

    Ok(())
}
