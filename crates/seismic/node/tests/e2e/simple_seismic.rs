//! Simple test: Deploy contract and send ONE seismic transaction

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

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
use std::{thread, time::Duration};
use tokio::sync::mpsc;

const WAIT_FOR_RECEIPT_SECONDS: u64 = 1;

sol! {
    interface SeismicOwnedCounter {
        function setNumber(uint256 newNumber) external;
        function getNumber() external view returns (uint256);
    }
}

/// Deployment bytecode for SeismicOwnedCounter
fn get_deploy_bytecode() -> Bytes {
    Bytes::from_static(&hex!("60806040525f5f8190b1503360015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610443806100575f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806324a7f0b71461004e57806343bd0d701461006a578063d09de08a14610088578063f2c9ecd814610092575b5f5ffd5b6100686004803603810190610063919061020e565b6100b0565b005b6100726100e5565b60405161007f9190610253565b60405180910390f35b6100906100fc565b005b61009a610140565b6040516100a79190610284565b60405180910390f35b805f8190b1507fd5d7fa14c63c3a6cb5e6dd4b4bb8c48d371a807bd306e9c09f1d61769963402c60405160405180910390a150565b5f600160025fb06100f691906102ca565b14905090565b5f5f81b08092919061010d90610327565b919050b1507f9ff5ccac5db99a217f56663c2490d2cb74f1512ec2f298bb1c8b7ffc56dae36e60405160405180910390a1565b5f60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101c7906103c8565b60405180910390fd5b5fb0905090565b5f5ffd5b5f819050919050565b6101ed816101db565b81146101f7575f5ffd5b50565b5f81359050610208816101e4565b92915050565b5f60208284031215610223576102226101d7565b5b5f610230848285016101fa565b91505092915050565b5f8115159050919050565b61024d81610239565b82525050565b5f6020820190506102665f830184610244565b92915050565b5f819050919050565b61027e8161026c565b82525050565b5f6020820190506102975f830184610275565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6102d48261026c565b91506102df8361026c565b9250826102ef576102ee61029d565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f610331826101db565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610363576103626102fa565b5b600182019050919050565b5f82825260208201905092915050565b7f4f6e6c79206f776e6572000000000000000000000000000000000000000000005f82015250565b5f6103b2600a8361036e565b91506103bd8261037e565b602082019050919050565b5f6020820190508181035f8301526103df816103a6565b905091905056fea2646970667358221220744adf2989c01da739959cd1d48c8130aec35f9efe6d318e57af981238dc44d764736f6c637829302e382e33312d646576656c6f702e323032352e312e31322b636f6d6d69742e3637366264656363005a"))
}

fn get_set_number_calldata(number: u64) -> Bytes {
    let call = SeismicOwnedCounter::setNumberCall { newNumber: U256::from(number) };
    Bytes::from(call.abi_encode())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_seismic_transaction() {
    println!("\n=== Simple Seismic Transaction Test ===\n");

    // Start node
    let (tx, mut rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    println!("1. Starting seismic-reth node...");
    SeismicRethTestCommand::run(tx, shutdown_rx).await;
    rx.recv().await.unwrap();
    println!("   ✓ Node is ready\n");

    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();

    thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

    // Create provider
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet: SeismicWallet<SeismicReth> = SeismicWallet::from(_wallet.inner);
    let wallet_address = wallet.default_signer().address();

    println!("   Wallet/Signer address: {:?}", wallet_address);

    let provider = SeismicSignedProvider::new(wallet, reqwest::Url::parse(&reth_rpc_url).unwrap())
        .await
        .unwrap();

    println!("2. Deploying SeismicOwnedCounter contract...");
    println!("   Wallet address: {:?}", wallet_address);

    // Deploy contract
    let deploy_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            get_deploy_bytecode(),
        ),
        TxKind::Create,
    );

    let pending_tx = provider.send_transaction(deploy_req).await.unwrap();
    let deploy_tx_hash = pending_tx.tx_hash();
    thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

    let receipt = provider.get_transaction_receipt(*deploy_tx_hash).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    let deploy_block = receipt.block_number.unwrap();

    println!("   ✓ Contract deployed at: {:?}", contract_addr);
    println!("   ✓ Deploy block: {}", deploy_block);
    println!("   ✓ Owner set to: {:?}\n", wallet_address);

    // Get current block info
    let latest_block_num = provider.get_block_number().await.unwrap();
    let latest_block = provider.get_block_by_number(latest_block_num.into()).await.unwrap().unwrap();
    let latest_block_hash = latest_block.header.hash;

    println!("3. Sending ONE seismic transaction (setNumber(42))...");
    println!("   Current block: {} (hash: {:?})", latest_block_num, latest_block_hash);

    // Build seismic transaction
    let mut set_num_tx = seismic_reth_tx_builder()
        .with_input(get_set_number_calldata(42))
        .with_to(contract_addr)
        .into()
        .seismic();

    // Set high gas limit
    set_num_tx.gas = Some(5_000_000);

    println!("   Built seismic transaction:");
    println!("     - type: {:?}", set_num_tx.transaction_type);
    println!("     - to: {:?}", set_num_tx.to);
    println!("     - gas: {:?}", set_num_tx.gas);
    println!("     - has seismic_elements: {}", set_num_tx.seismic_elements.is_some());

    // Send transaction
    let pending_tx = match provider.send_transaction(set_num_tx).await {
        Ok(tx) => {
            println!("   ✓ Transaction accepted by mempool");
            tx
        }
        Err(e) => {
            eprintln!("   ❌ Failed to send transaction: {:?}", e);
            shutdown_tx.send(()).await.unwrap();
            panic!("Failed to send seismic transaction");
        }
    };

    let tx_hash = pending_tx.tx_hash();
    println!("   Transaction hash: {:?}", tx_hash);
    thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

    // Get receipt
    let receipt = match provider.get_transaction_receipt(*tx_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            eprintln!("   ❌ No receipt found");
            shutdown_tx.send(()).await.unwrap();
            panic!("No receipt for transaction");
        }
        Err(e) => {
            eprintln!("   ❌ Failed to get receipt: {:?}", e);
            shutdown_tx.send(()).await.unwrap();
            panic!("Get receipt failed");
        }
    };

    println!("\n4. Checking transaction result...");
    println!("   Status: {}", if receipt.status() { "SUCCESS" } else { "FAILED" });
    println!("   Gas used: {}", receipt.gas_used);
    println!("   Block: {:?}", receipt.block_number);

    if !receipt.status() {
        eprintln!("\n   ❌ TRANSACTION REVERTED!");
        eprintln!("   This means the seismic transaction reached the chain but the contract rejected it.");
        eprintln!("   With only {} gas used (base tx cost is 21000), it reverted almost immediately.", receipt.gas_used);
        eprintln!("\n   Possible reasons:");
        eprintln!("   - Owner check failing (owner stored during deployment vs msg.sender during tx)");
        eprintln!("   - Seismic transaction validation failing before contract execution");
        eprintln!("   - Contract state not being read correctly with seismic opcodes");

        shutdown_tx.send(()).await.unwrap();
        thread::sleep(Duration::from_secs(1));
        panic!("Seismic transaction reverted - investigation needed");
    }

    println!("   ✓ Transaction succeeded!\n");

    shutdown_tx.send(()).await.unwrap();
    thread::sleep(Duration::from_secs(1));

    println!("=== ✅ Simple Seismic Transaction Test PASSED ===\n");
}
