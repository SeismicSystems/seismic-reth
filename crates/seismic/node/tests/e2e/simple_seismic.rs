//! Simple test: Deploy contract and send ONE seismic transaction

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use alloy_network::{ReceiptResponse, TransactionBuilder};
use alloy_primitives::{aliases::SUInt, hex, Bytes, TxKind, Uint, SU256, U256};
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
        function setNumber(suint256 newNumber) public;
        function getNumber() public view returns (uint256);
        function isOdd() public view returns (bool);
    }
}

/// Deployment bytecode for SeismicOwnedCounter
fn get_deploy_bytecode() -> Bytes {
    Bytes::from_static(&hex!("60806040525f5f8190b1503360015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506103eb806100575f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806324a7f0b71461004e57806343bd0d701461006a578063d09de08a14610088578063f2c9ecd814610092575b5f5ffd5b610068600480360381019061006391906101b6565b6100b0565b005b6100726100b9565b60405161007f91906101fb565b60405180910390f35b6100906100d0565b005b61009a6100e8565b6040516100a7919061022c565b60405180910390f35b805f8190b15050565b5f600160025fb06100ca9190610272565b14905090565b5f5f81b0809291906100e1906102cf565b919050b150565b5f60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610178576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161016f90610370565b60405180910390fd5b5fb0905090565b5f5ffd5b5f819050919050565b61019581610183565b811461019f575f5ffd5b50565b5f813590506101b08161018c565b92915050565b5f602082840312156101cb576101ca61017f565b5b5f6101d8848285016101a2565b91505092915050565b5f8115159050919050565b6101f5816101e1565b82525050565b5f60208201905061020e5f8301846101ec565b92915050565b5f819050919050565b61022681610214565b82525050565b5f60208201905061023f5f83018461021d565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61027c82610214565b915061028783610214565b92508261029757610296610245565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6102d982610183565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361030b5761030a6102a2565b5b600182019050919050565b5f82825260208201905092915050565b7f4f6e6c79206f776e6572000000000000000000000000000000000000000000005f82015250565b5f61035a600a83610316565b915061036582610326565b602082019050919050565b5f6020820190508181035f8301526103878161034e565b905091905056fea2646970667358221220ed9296ceeba178e7dc3fa9c5092f3fe3d2784f534a279605289ba063e123669064736f6c637829302e382e33312d646576656c6f702e323032352e31312e31322b636f6d6d69742e3637366264656363005a"))
}

fn get_set_number_calldata(number: u64) -> Bytes {
    let uint = U256::from(number);
    let call = SeismicOwnedCounter::setNumberCall { newNumber: SUInt(uint) };
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
    let latest_block =
        provider.get_block_by_number(latest_block_num.into()).await.unwrap().unwrap();
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

    println!("Receipt: {receipt:?}");

    println!("\n4. Checking transaction result...");
    println!("   Status: {}", if receipt.status() { "SUCCESS" } else { "FAILED" });
    println!("   Gas used: {}", receipt.gas_used);
    println!("   Block: {:?}", receipt.block_number);

    if !receipt.status() {
        eprintln!("\n   ❌ TRANSACTION REVERTED!");
        eprintln!(
            "   This means the seismic transaction reached the chain but the contract rejected it."
        );
        eprintln!(
            "   With only {} gas used (base tx cost is 21000), it reverted almost immediately.",
            receipt.gas_used
        );
        eprintln!("\n   Possible reasons:");
        eprintln!(
            "   - Owner check failing (owner stored during deployment vs msg.sender during tx)"
        );
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

#[tokio::test(flavor = "multi_thread")]
async fn test_vanilla_call_is_odd() {
    println!("\n=== Vanilla eth_call to isOdd() Test ===\n");

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

    let provider = SeismicSignedProvider::new(wallet, reqwest::Url::parse(&reth_rpc_url).unwrap())
        .await
        .unwrap();

    println!("2. Deploying SeismicOwnedCounter contract...");
    println!("   Wallet address: {:?}", wallet_address);

    // Deploy contract with regular transaction
    let deploy_req = seismic_reth_tx_builder()
        .with_input(get_deploy_bytecode())
        .with_kind(TxKind::Create)
        .into();

    let pending_tx = provider.send_transaction(deploy_req).await.unwrap();
    let deploy_tx_hash = pending_tx.tx_hash();
    thread::sleep(Duration::from_secs(WAIT_FOR_RECEIPT_SECONDS));

    let receipt = provider.get_transaction_receipt(*deploy_tx_hash).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    let deploy_block = receipt.block_number.unwrap();

    println!("   ✓ Contract deployed at: {:?}", contract_addr);
    println!("   ✓ Deploy block: {}\n", deploy_block);

    println!("3. Calling isOdd() with vanilla eth_call...");

    // Build the call data for isOdd()
    let is_odd_call = SeismicOwnedCounter::isOddCall {};
    let call_data = Bytes::from(is_odd_call.abi_encode());

    println!("   Call data: {:?}", call_data);

    // Make eth_call using TransactionRequest
    let call_tx = seismic_reth_tx_builder().with_to(contract_addr).with_input(call_data).into();

    let call_result = provider.call(call_tx).await.unwrap();

    println!("   Raw result: {:?}", call_result);

    // Decode the result
    let result = SeismicOwnedCounter::isOddCall::abi_decode_returns(&call_result).unwrap();

    println!("   ✓ isOdd() returned: {}", result);
    println!("   Expected: false (number starts at 0)\n");

    assert_eq!(result, false, "isOdd() should return false when number is 0");

    shutdown_tx.send(()).await.unwrap();
    thread::sleep(Duration::from_secs(1));

    println!("=== ✅ Vanilla eth_call Test PASSED ===\n");
}
