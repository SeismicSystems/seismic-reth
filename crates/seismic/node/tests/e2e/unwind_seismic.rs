//! E2E test for unwinding seismic transactions
//!
//! This test verifies that reth's unwind functionality works correctly with seismic transactions
//! by:
//! 1. Deploying a SeismicOwnedCounter contract
//! 2. Executing 5 seismic transactions: setNumber(1), setNumber(2), ..., setNumber(5)
//! 3. Stopping the node and unwinding to different block heights
//! 4. Restarting the node and verifying state with signed getNumber() calls

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)] // Test file - panics are acceptable

use alloy_network::{ReceiptResponse, TransactionBuilder};
use alloy_primitives::{hex, Bytes, TxKind, U256};
use alloy_provider::Provider;
use alloy_sol_types::{sol, SolCall};
use reth_e2e_test_utils::wallet::Wallet;
use reth_seismic_node::utils::test_utils::SeismicRethTestCommand;
use seismic_alloy_network::{
    reth::builder::seismic_reth_tx_builder, wallet::SeismicWallet, SeismicReth,
};
use seismic_alloy_provider::{SeismicProviderExt, SeismicSignedProvider};
use seismic_alloy_rpc_types::SeismicTransactionRequest;
use std::{process::Command as StdCommand, thread, time::Duration};
use tokio::sync::mpsc;

const WAIT_FOR_RECEIPT_SECONDS: u64 = 1;

/*
SeismicOwnedCounter contract interface
Note: We use uint256 in the ABI even though the contract uses suint256,
because the ABI encoding is identical and the sol! macro doesn't understand suint256.
*/
sol! {
    interface SeismicOwnedCounter {
        function setNumber(uint256 newNumber) external;
        function getNumber() external view returns (uint256);
    }
}

/// Deployment bytecode for SeismicOwnedCounter
fn get_deploy_bytecode() -> Bytes {
    Bytes::from_static(&hex!("60806040525f5f8190b1503360015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610443806100575f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806324a7f0b71461004e57806343bd0d701461006a578063d09de08a14610088578063f2c9ecd814610092575b5f5ffd5b6100686004803603810190610063919061020e565b6100b0565b005b6100726100e5565b60405161007f9190610253565b60405180910390f35b6100906100fc565b005b61009a610140565b6040516100a79190610284565b60405180910390f35b805f8190b1507fd5d7fa14c63c3a6cb5e6dd4b4bb8c48d371a807bd306e9c09f1d61769963402c60405160405180910390a150565b5f600160025fb06100f691906102ca565b14905090565b5f5f81b08092919061010d90610327565b919050b1507f9ff5ccac5db99a217f56663c2490d2cb74f1512ec2f298bb1c8b7ffc56dae36e60405160405180910390a1565b5f60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101c7906103c8565b60405180910390fd5b5fb0905090565b5f5ffd5b5f819050919050565b6101ed816101db565b81146101f7575f5ffd5b50565b5f81359050610208816101e4565b92915050565b5f60208284031215610223576102226101d7565b5b5f610230848285016101fa565b91505092915050565b5f8115159050919050565b61024d81610239565b82525050565b5f6020820190506102665f830184610244565b92915050565b5f819050919050565b61027e8161026c565b82525050565b5f6020820190506102975f830184610275565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6102d48261026c565b91506102df8361026c565b9250826102ef576102ee61029d565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610331826101db565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610363576103626102fa565b5b600182019050919050565b5f82825260208201905092915050565b7f4f6e6c79206f776e6572000000000000000000000000000000000000000000005f82015250565b5f6103b2600a8361036e565b91506103bd8261037e565b602082019050919050565b5f6020820190508181035f8301526103df816103a6565b905091905056fea2646970667358221220744adf2989c01da739959cd1d48c8130aec35f9efe6d318e57af981238dc44d764736f6c637829302e382e33312d646576656c6f702e323032352e312e31322b636f6d6d69742e3637366264656363005a"))
}

/// Generates calldata for setNumber(uint256) function call
/// Uses the sol! macro generated function to create properly encoded calldata
fn get_set_number_calldata(number: u64) -> Bytes {
    let call = SeismicOwnedCounter::setNumberCall { newNumber: U256::from(number) };
    Bytes::from(call.abi_encode())
}

/// Generates calldata for getNumber() function call
/// Uses the sol! macro generated function to create properly encoded calldata
fn get_get_number_calldata() -> Bytes {
    let call = SeismicOwnedCounter::getNumberCall {};
    Bytes::from(call.abi_encode())
}

/// Helper function to run the seismic-reth unwind command
///
/// This executes `cargo run --bin seismic-reth -- stage unwind --datadir <datadir> to-block
/// <target>` and handles errors by printing full stdout/stderr for debugging.
fn run_unwind_command(data_dir: &std::path::Path, target_block: u64) {
    println!("      Running: seismic-reth stage unwind to-block {}", target_block);

    let unwind_output = StdCommand::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("seismic-reth")
        .arg("--")
        .arg("stage")
        .arg("unwind")
        .arg("--datadir")
        .arg(data_dir.to_str().unwrap())
        .arg("to-block")
        .arg(target_block.to_string())
        .output()
        .expect("Failed to spawn unwind command");

    if !unwind_output.status.success() {
        let stdout = String::from_utf8_lossy(&unwind_output.stdout);
        let stderr = String::from_utf8_lossy(&unwind_output.stderr);
        eprintln!("\n❌ Unwind command failed for block {}", target_block);
        eprintln!("Exit status: {}", unwind_output.status);
        eprintln!("\n--- STDOUT ---\n{}", stdout);
        eprintln!("\n--- STDERR ---\n{}", stderr);
        panic!("Unwind command failed with exit code: {:?}", unwind_output.status.code());
    }

    println!("      ✓ Unwind completed successfully");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unwind_seismic_transactions() {
    println!("\n=== Starting Seismic Transaction Unwind E2E Test ===\n");

    // Start the seismic reth node
    let (tx, mut rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    println!("1. Starting seismic-reth node...");
    SeismicRethTestCommand::run(tx, shutdown_rx).await;

    // Wait for node to be ready
    rx.recv().await.unwrap();
    println!("   ✓ Node is ready\n");

    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();

    thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

    // Create provider
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet: SeismicWallet<SeismicReth> = SeismicWallet::from(_wallet.inner);

    let provider = SeismicSignedProvider::new(wallet, reqwest::Url::parse(&reth_rpc_url).unwrap())
        .await
        .unwrap();

    println!("2. Deploying SeismicOwnedCounter contract...");

    // Deploy contract - cannot be seismic since CREATE transactions don't support encryption
    let deploy_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            get_deploy_bytecode(),
        ),
        TxKind::Create,
    );

    eprintln!("DEBUG: Deploying contract (non-seismic CREATE tx)");
    let pending_tx = match provider.send_transaction(deploy_req).await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("❌ Failed to deploy contract: {:?}", e);
            eprintln!("❌ Error details: {:#?}", e);
            panic!("Contract deployment failed");
        }
    };
    let deploy_tx_hash = pending_tx.tx_hash();
    thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

    let receipt = match provider.get_transaction_receipt(*deploy_tx_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => panic!("No receipt found for deployment transaction"),
        Err(e) => {
            eprintln!("❌ Failed to get deployment receipt: {:?}", e);
            panic!("Get receipt failed");
        }
    };
    let contract_addr = receipt.contract_address.unwrap();
    let deploy_block = receipt.block_number.unwrap();

    println!("   ✓ Contract deployed at: {:?}", contract_addr);
    println!("   ✓ Deploy block: {}\n", deploy_block);

    // Send 5 seismic setNumber() transactions
    println!("3. Sending 5 seismic setNumber() transactions...");
    let mut block_numbers = vec![deploy_block];

    for i in 1..=5 {
        // Check current block before sending transaction
        let latest_block_num = provider.get_block_number().await.unwrap();
        let latest_block = provider.get_block_by_number(latest_block_num.into()).await.unwrap().unwrap();
        let latest_block_hash = latest_block.header.hash;

        eprintln!("\nDEBUG ===== Transaction {} =====", i);
        eprintln!("DEBUG: Current block number: {}", latest_block_num);
        eprintln!("DEBUG: Current block hash: {:?}", latest_block_hash);

        // Build transaction and set a high gas limit to bypass estimation issues
        // IMPORTANT: Must call .seismic() to mark it as a seismic transaction!
        let mut set_num_tx = seismic_reth_tx_builder()
            .with_input(get_set_number_calldata(i))
            .with_to(contract_addr)
            .into()
            .seismic();

        // Set very high gas limit to bypass estimation
        set_num_tx.gas = Some(5_000_000);

        eprintln!("DEBUG: Built seismic tx (type 74) with gas limit {}", set_num_tx.gas.unwrap());

        // Clone for error reporting
        let set_num_tx_clone = set_num_tx.clone();

        let pending_tx = match provider.send_transaction(set_num_tx).await {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("❌ Failed to send transaction {}: {:?}", i, e);
                eprintln!("❌ Error details: {:#?}", e);
                panic!("Transaction send failed");
            }
        };
        let tx_hash = pending_tx.tx_hash();
        thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

        let receipt = match provider.get_transaction_receipt(*tx_hash).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                eprintln!("❌ No receipt found for transaction {}", i);
                panic!("No receipt for transaction {}", i);
            }
            Err(e) => {
                eprintln!("❌ Failed to get receipt for transaction {}: {:?}", i, e);
                panic!("Get receipt failed for transaction {}", i);
            }
        };

        eprintln!("DEBUG: Receipt for tx {}: status={}, gas_used={:?}", i, receipt.status(), receipt.gas_used);
        if !receipt.status() {
            eprintln!("❌ Transaction {} reverted!", i);
            eprintln!("❌ Gas used: {}", receipt.gas_used);
            eprintln!("❌ Block number: {:?}", receipt.block_number);
            eprintln!("❌ Transaction hash: {:?}", receipt.transaction_hash);

            // Try to get more details by calling eth_call to see the revert reason
            eprintln!("\n❌ Attempting to get revert reason by replaying transaction...");
            let call_result = provider.call(set_num_tx_clone).await;
            match call_result {
                Ok(output) => {
                    eprintln!("❌ Call succeeded (unexpected): {:?}", output);
                }
                Err(e) => {
                    eprintln!("❌ Call reverted with error: {:?}", e);
                }
            }

            panic!("Transaction {} reverted - see details above", i);
        }
        assert!(receipt.status(), "Transaction {} reverted", i);

        let block_num = receipt.block_number.unwrap();
        block_numbers.push(block_num);

        println!("   ✓ setNumber({}) executed in block {}", i, block_num);
    }

    println!("\n4. Verifying final state (should be 5)...");

    // Verify state is 5
    let output = provider
        .seismic_call(alloy_provider::SendableTx::Builder(
            TransactionBuilder::<SeismicReth>::with_to(
                TransactionBuilder::<SeismicReth>::with_input(
                    SeismicTransactionRequest::default(),
                    get_get_number_calldata(),
                ),
                contract_addr,
            ),
        ))
        .await
        .unwrap();

    let current_value = U256::from_be_slice(&output);
    assert_eq!(current_value, U256::from(5), "Expected value to be 5 before unwind");
    println!("   ✓ getNumber() returned: {}\n", current_value);

    // Stop the node for unwind operations
    println!("5. Stopping node for unwind operations...");
    shutdown_tx.send(()).await.unwrap();
    thread::sleep(Duration::from_secs(2));
    println!("   ✓ Node stopped\n");

    let data_dir = SeismicRethTestCommand::data_dir();

    // Now unwind to each block one by one, verifying state at each step
    // We have blocks: [deploy_block, block1, block2, block3, block4, block5]
    // After each setNumber(n), the state should be n
    println!("6. Testing unwind to each block sequentially...\n");

    // Unwind to block 4 (should have value 4)
    for target_idx in (1..5).rev() {
        let unwind_target = block_numbers[target_idx];
        let expected_value = target_idx as u64; // After setNumber(target_idx)

        println!(
            "   6.{}) Unwinding to block {} (expecting value {})...",
            5 - target_idx,
            unwind_target,
            expected_value
        );

        // Run unwind command
        run_unwind_command(&data_dir, unwind_target);

        // Restart node
        let (tx_restart, mut rx_restart) = mpsc::channel(1);
        let (_shutdown_restart, shutdown_rx_restart) = mpsc::channel(1);
        SeismicRethTestCommand::run(tx_restart, shutdown_rx_restart).await;
        rx_restart.recv().await.unwrap();
        thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

        // Recreate provider
        let _wallet_restart = Wallet::default().with_chain_id(chain_id);
        let wallet_restart: SeismicWallet<SeismicReth> = SeismicWallet::from(_wallet_restart.inner);
        let provider_restart =
            SeismicSignedProvider::new(wallet_restart, reqwest::Url::parse(&reth_rpc_url).unwrap())
                .await
                .unwrap();

        // Verify state
        let output = provider_restart
            .seismic_call(alloy_provider::SendableTx::Builder(
                TransactionBuilder::<SeismicReth>::with_to(
                    TransactionBuilder::<SeismicReth>::with_input(
                        SeismicTransactionRequest::default(),
                        get_get_number_calldata(),
                    ),
                    contract_addr,
                ),
            ))
            .await
            .unwrap();

        let unwound_value = U256::from_be_slice(&output);
        assert_eq!(
            unwound_value,
            U256::from(expected_value),
            "Expected value to be {} after unwinding to block {}, but got {}",
            expected_value,
            unwind_target,
            unwound_value
        );

        println!("      ✓ Verified: getNumber() = {} (CORRECT!)", unwound_value);

        // Stop node for next unwind
        let (shutdown_tx_next, _shutdown_rx_next) = mpsc::channel(1);
        shutdown_tx_next.send(()).await.unwrap();
        thread::sleep(Duration::from_secs(2));
    }

    println!("\n=== ✅ All Seismic Transaction Unwind Tests PASSED ===");
    println!("   Tested unwinding through 4 blocks, verifying state at each step");
    println!("   All state values correctly reverted after each unwind\n");
}
