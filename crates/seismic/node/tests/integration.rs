use alloy_primitives::{hex, Address, Bytes, TxKind, U256};
use alloy_rpc_types::{Block, Header, Receipt, Transaction, TransactionRequest};
use assert_cmd::Command;
use reqwest::Client;
use reth_chainspec::{ChainSpec, DEV};
use reth_e2e_test_utils::wallet::{self, Wallet};
use reth_node_builder::engine_tree_config::DEFAULT_BACKUP_THRESHOLD;
use reth_rpc_eth_api::EthApiClient;
use seismic_node::utils::test_utils::{
    get_signed_seismic_tx_bytes, get_unsigned_seismic_tx_request, ContractTestContext,
    IntegrationTestContext, UnitTestContext,
};
use seismic_rpc_api::rpc::SeismicApiClient;
use serde_json::{json, Value};
use std::{path::PathBuf, str::FromStr, thread, time::Duration};
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
use tokio::process::Child;

struct RethCommand(Child);

impl RethCommand {
    fn data_dir() -> PathBuf {
        static TEMP_DIR: once_cell::sync::Lazy<tempfile::TempDir> =
            once_cell::sync::Lazy::new(|| tempfile::tempdir().unwrap());
        TEMP_DIR.path().to_path_buf()
    }
    fn run() -> RethCommand {
        let cmd = Command::cargo_bin("seismic-reth").unwrap();
        let cmd_str = cmd.get_program().to_str().unwrap();
        let child = tokio::process::Command::new(cmd_str)
            .arg("node")
            .arg("--datadir")
            .arg(RethCommand::data_dir().to_str().unwrap())
            .arg("--dev")
            .arg("--dev.block-max-transactions")
            .arg("1")
            .arg("--tee.mock-server")
            .arg("-vvvvv")
            .spawn()
            .expect("Failed to start the binary");
        RethCommand(child)
    }
    fn chain_id() -> u64 {
        DEV.chain().into()
    }
}

impl Drop for RethCommand {
    fn drop(&mut self) {
        // kill the process
        thread::sleep(Duration::from_secs(2));
        let pid = self.0.id().unwrap();
        if let Some(process) = System::new_all().process(Pid::from_u32(pid)) {
            process.kill();
        }
    }
}

// this is the same test as basic.rs but with actual RPC calls and standalone reth instance
#[tokio::test]
async fn test_seismic_reth_rpc() {
    let itx = IntegrationTestContext::load();

    const RETH_RPC_URL: &str = "http://127.0.0.1:8545";
    // Step 1: Start the binary
    let _cmd = RethCommand::run();

    // Step 2: Allow the binary some time to start
    thread::sleep(Duration::from_secs(5));

    // Step 3: Send RPC calls
    let client = Client::new();

    // Deploy the contract
    let deploy_tx = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [],
        "id": 1
    });

    let deploy_response = client
        .post(RETH_RPC_URL)
        .json(&deploy_tx)
        .send()
        .await
        .expect("Failed to send deploy transaction");

    let deploy_result: serde_json::Value = deploy_response.json().await.unwrap();
    println!("Deploy Result: {:?}", deploy_result);
    assert!(deploy_result["result"] == itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt_tx = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [itx.tx_hashes[0]],
        "id": 1
    });

    let receipt_response = client
        .post(RETH_RPC_URL)
        .json(&receipt_tx)
        .send()
        .await
        .expect("Failed to get transaction receipt");
    let receipt_result: Value = receipt_response.json().await.unwrap();
    println!("Transaction Receipt: {:?}", receipt_result);
    assert!(receipt_result["result"]["status"] == "0x1");

    // Step 1: Make sure the code of the contract is deployed
    let get_code = json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [itx.contract, "latest"],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&get_code)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_getCode Response: {:?}", response);
    assert!(response["result"] == itx.code);

    // Step 2: eth_call to check the parity. Should be 0
    let eth_call = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [itx.signed_calls[0]],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&eth_call)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    assert!(response["result"] == itx.encrypted_outputs[0]);

    // Step 3: Send transaction to set suint
    let send_transaction = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [itx.raw_txs[0]],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&send_transaction)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_sendRawTransaction Response: {:?}", response);
    assert!(response["result"] == itx.tx_hashes[1]);
    thread::sleep(Duration::from_secs(1));

    // Step 4: Get the transaction receipt
    let get_receipt = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [itx.tx_hashes[1]],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&get_receipt)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_getTransactionReceipt Response: {:?}", response);
    assert!(response["result"]["status"] == "0x1");

    // Step 5: Final eth_call to check the parity. Should be 1
    let eth_call_final = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [itx.signed_calls[1]],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&eth_call_final)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    assert!(response["result"] == itx.encrypted_outputs[1]);
}

#[tokio::test]
async fn test_seismic_reth_rpc_new() {
    const RETH_RPC_URL: &str = "http://127.0.0.1:8545";
    // Step 1: Start the binary
    let _cmd = RethCommand::run();
    let chain_id = RethCommand::chain_id();

    // Step 2: Allow the binary some time to start
    thread::sleep(Duration::from_secs(5));

    // Step 3: Send RPC calls
    let client = jsonrpsee::http_client::HttpClientBuilder::default().build(RETH_RPC_URL).unwrap();

    let wallet = Wallet::default().with_chain_id(chain_id);
    let nonce = 0;

    let seismic_tx_request = get_unsigned_seismic_tx_request(
        &wallet.inner,
        nonce,
        TxKind::Create,
        chain_id,
        ContractTestContext::get_deploy_input_plaintext(),
    )
    .await;

    let gas = EthApiClient::<Transaction, Block, Receipt, Header>::estimate_gas(
        &client,
        seismic_tx_request,
        None,
        None,
    )
    .await
    .unwrap();
    println!("gas: {:?}", gas);
    assert!(gas > U256::ZERO);
}

#[tokio::test]
async fn test_seismic_reth_backup() {
    let itx = IntegrationTestContext::load();
    let chain_id = DEV.chain;

    const RETH_RPC_URL: &str = "http://127.0.0.1:8545";
    // Step 1: Start the binary
    let _cmd = RethCommand::run();

    // Step 2: Allow the binary some time to start
    thread::sleep(Duration::from_secs(5));

    // Step 3: Send RPC calls
    let client = Client::new();

    // Deploy the contract
    let deploy_tx = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [itx.deploy_tx],
        "id": 1
    });

    let deploy_response = client
        .post(RETH_RPC_URL)
        .json(&deploy_tx)
        .send()
        .await
        .expect("Failed to send deploy transaction");

    let deploy_result: serde_json::Value = deploy_response.json().await.unwrap();
    println!("Deploy Result: {:?}", deploy_result);
    assert!(deploy_result["result"] == itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt_tx = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [itx.tx_hashes[0]],
        "id": 1
    });

    let receipt_response = client
        .post(RETH_RPC_URL)
        .json(&receipt_tx)
        .send()
        .await
        .expect("Failed to get transaction receipt");
    let receipt_result: Value = receipt_response.json().await.unwrap();
    println!("Transaction Receipt: {:?}", receipt_result);
    assert!(receipt_result["result"]["status"] == "0x1");

    // getting contract address
    let contract_addr =
        Address::from_str(receipt_result["result"]["contractAddress"].as_str().unwrap()).unwrap();

    // send enough transaction to trigger a backup
    let mut nonce = 1;
    let wallet = Wallet::default().with_chain_id(chain_id.into());
    for _ in 0..DEFAULT_BACKUP_THRESHOLD + 1 {
        let input = Bytes::from_static(&hex!(
            "24a7f0b70000000000000000000000000000000000000000000000000000000000000003"
        ));
        let raw_tx = get_signed_seismic_tx_bytes(
            &wallet.inner,
            nonce,
            alloy_primitives::TxKind::Call(contract_addr),
            chain_id.id(),
            input.clone(),
        )
        .await;
        nonce += 1;

        // interact with the contract
        let tx = json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx.to_string()],
            "id": 1
        });

        let tx_response = client
            .post(RETH_RPC_URL)
            .json(&tx)
            .send()
            .await
            .expect("Failed to send deploy transaction");

        let tx_result: serde_json::Value = tx_response.json().await.unwrap();
        println!("Transaction Result: {:?}", tx_result);
    }

    thread::sleep(Duration::from_secs(10));

    let backup_path = PathBuf::from(format!("{}_backup", RethCommand::data_dir().display(),));
    let data_dir = RethCommand::data_dir();
    // Compare contents of backup and data directories
    let mut data_dir_files: Vec<_> =
        std::fs::read_dir(&data_dir).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    data_dir_files.sort();

    let mut backup_files: Vec<_> =
        std::fs::read_dir(&backup_path).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    backup_files.sort();

    assert_eq!(
        data_dir_files, backup_files,
        "Backup directory contents do not match data directory contents.\nData dir: {:?}\nBackup dir: {:?}",
        data_dir_files, backup_files
    );
}
