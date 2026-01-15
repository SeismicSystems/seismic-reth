//! Test seismic transactions with REGULAR storage opcodes (not private storage)

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
use seismic_alloy_provider::SeismicSignedProvider;
use seismic_alloy_rpc_types::SeismicTransactionRequest;
use std::{thread, time::Duration};
use tokio::sync::mpsc;

const WAIT_FOR_RECEIPT_SECONDS: u64 = 1;

sol! {
    interface SimpleStorage {
        function set(uint256 value) external;
        function get() external view returns (uint256);
    }
}

/// Simple storage contract WITHOUT seismic opcodes - uses regular SLOAD/SSTORE
/// Solidity: contract SimpleStorage { uint256 public storedData; function set(uint256 x) public {
/// storedData = x; } function get() public view returns (uint256) { return storedData; } }
fn get_deploy_bytecode() -> Bytes {
    Bytes::from_static(&hex!("608060405234801561000f575f5ffd5b506101438061001d5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c806360fe47b1146100385780636d4ce63c14610054575b5f5ffd5b610052600480360381019061004d91906100ba565b610072565b005b61005c61007b565b60405161006991906100f4565b60405180910390f35b805f8190555050565b5f5f549050b0565b5f5ffd5b5f819050919050565b61009881610086565b81146100a2575f5ffd5b50565b5f813590506100b38161008f565b92915050565b5f602082840312156100ce576100cd610082565b5b5f6100db848285016100a5565b91505092915050565b6100ed81610086565b82525050565b5f6020820190506101065f8301846100e4565b9291505056fea26469706673582212206aa3f34af3fc4fc03d98dab2fb5a08f3b1a51ec03a5a8da9f51eefb0f5b6ecd964736f6c637829302e382e33312d646576656c6f702e323032352e312e31322b636f6d6d69742e3637366264656363005a"))
}

fn get_set_calldata(value: u64) -> Bytes {
    let call = SimpleStorage::setCall { value: U256::from(value) };
    Bytes::from(call.abi_encode())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_tx_with_regular_storage() {
    println!("\n=== Seismic Transaction with Regular Storage Test ===\n");

    // Start node
    let (tx, mut rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    println!("1. Starting seismic-reth node...");
    SeismicRethTestCommand::run(tx, shutdown_rx).await;
    rx.recv().await.unwrap();
    println!("   ✓ Node is ready\\n");

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

    println!("2. Deploying SimpleStorage contract (regular SLOAD/SSTORE)...");
    println!("   Wallet address: {:?}", wallet_address);

    // Deploy contract with regular transaction
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
    println!("   ✓ Deploy block: {}\\n", deploy_block);

    println!("3. Sending seismic transaction to set storage value to 42...");

    // Build seismic transaction with regular storage operations
    let mut set_tx = seismic_reth_tx_builder()
        .with_input(get_set_calldata(42))
        .with_to(contract_addr)
        .into()
        .seismic();

    set_tx.gas = Some(5_000_000);

    println!("   Built seismic transaction");

    // Send transaction
    let pending_tx = match provider.send_transaction(set_tx).await {
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

    println!("\\n4. Checking transaction result...");
    println!("   Status: {}", if receipt.status() { "SUCCESS" } else { "FAILED" });
    println!("   Gas used: {}", receipt.gas_used);
    println!("   Block: {:?}", receipt.block_number);

    if !receipt.status() {
        eprintln!("\\n   ❌ TRANSACTION REVERTED!");
        eprintln!("   Gas used: {}", receipt.gas_used);
        shutdown_tx.send(()).await.unwrap();
        thread::sleep(Duration::from_secs(1));
        panic!("Seismic transaction with regular storage reverted");
    }

    println!("   ✓ Transaction succeeded!\\n");

    shutdown_tx.send(()).await.unwrap();
    thread::sleep(Duration::from_secs(1));

    println!("=== ✅ Seismic Transaction with Regular Storage Test PASSED ===\\n");
}
