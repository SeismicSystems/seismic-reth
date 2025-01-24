<<<<<<< HEAD
//! This file is used to test the seismic node.
=======
>>>>>>> seismic
use alloy_primitives::{hex, Address, Bytes, TxKind, U256};
use alloy_rpc_types::{Block, Header, Transaction, TransactionInput, TransactionReceipt};
use assert_cmd::Command;
use reqwest::Client;
use reth_chainspec::DEV;
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_builder::engine_tree_config::DEFAULT_BACKUP_THRESHOLD;
use reth_rpc_eth_api::EthApiClient;
use seismic_node::utils::test_utils::{
    client_decrypt, get_nonce, get_signed_seismic_tx_bytes, get_unsigned_seismic_tx_request,
    ContractTestContext, IntegrationTestContext,
};
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
    fn url() -> String {
        format!("http://127.0.0.1:8545")
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

#[tokio::test]
async fn integration_test() {
    let _cmd = RethCommand::run();
    thread::sleep(Duration::from_secs(5));

    test_seismic_reth_backup().await;
    test_seismic_reth_rpc().await;
}

// this is the same test as basic.rs but with actual RPC calls and standalone reth instance
async fn test_seismic_reth_rpc() {
    let reth_rpc_url = RethCommand::url();
    let chain_id = RethCommand::chain_id();
    let client = jsonrpsee::http_client::HttpClientBuilder::default().build(reth_rpc_url).unwrap();
    let wallet = Wallet::default().with_chain_id(chain_id);

    let tx_hash =
        EthApiClient::<Transaction, Block, TransactionReceipt, Header>::send_raw_transaction(
            &client,
            get_signed_seismic_tx_bytes(
                &wallet.inner,
                get_nonce(&client, wallet.inner.address()).await,
                TxKind::Create,
                chain_id,
                ContractTestContext::get_deploy_input_plaintext(),
            )
            .await,
        )
        .await
        .unwrap();
    // assert_eq!(tx_hash, itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));
    println!("eth_sendRawTransaction deploying contract tx_hash: {:?}", tx_hash);

    // Get the transaction receipt
    let receipt =
        EthApiClient::<Transaction, Block, TransactionReceipt, Header>::transaction_receipt(
            &client, tx_hash,
        )
        .await
        .unwrap()
        .unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    println!(
        "eth_getTransactionReceipt getting contract deployment transaction receipt: {:?}",
        receipt
    );
    assert_eq!(receipt.status(), true);

    // Make sure the code of the contract is deployed
    let code = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::get_code(
        &client,
        contract_addr,
        None,
    )
    .await
    .unwrap();
    assert_eq!(ContractTestContext::get_code(), code);
    println!("eth_getCode getting contract deployment code: {:?}", code);

    // eth_call to check the parity. Should be 0
    let output = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::call(
        &client,
        reth_rpc_eth_api::types::SeismicCallRequest::Bytes(
            get_signed_seismic_tx_bytes(
                &wallet.inner,
                get_nonce(&client, wallet.inner.address()).await,
                TxKind::Call(contract_addr),
                chain_id,
                ContractTestContext::get_is_odd_input_plaintext(),
            )
            .await,
        ),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let decrypted_output =
        client_decrypt(&wallet.inner, get_nonce(&client, wallet.inner.address()).await, &output)
            .await;
    println!("eth_call decrypted output: {:?}", decrypted_output);
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::ZERO);

    // Send transaction to set suint
    let tx_hash =
        EthApiClient::<Transaction, Block, TransactionReceipt, Header>::send_raw_transaction(
            &client,
            get_signed_seismic_tx_bytes(
                &wallet.inner,
                get_nonce(&client, wallet.inner.address()).await,
                TxKind::Call(contract_addr),
                chain_id,
                ContractTestContext::get_set_number_input_plaintext(),
            )
            .await,
        )
        .await
        .unwrap();
    println!("eth_sendRawTransaction setting number transaction tx_hash: {:?}", tx_hash);
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt =
        EthApiClient::<Transaction, Block, TransactionReceipt, Header>::transaction_receipt(
            &client, tx_hash,
        )
        .await
        .unwrap()
        .unwrap();
    println!("eth_getTransactionReceipt getting set_number transaction receipt: {:?}", receipt);
    assert_eq!(receipt.status(), true);

    // Final eth_call to check the parity. Should be 1
    let output = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::call(
        &client,
        reth_rpc_eth_api::types::SeismicCallRequest::Bytes(
            get_signed_seismic_tx_bytes(
                &wallet.inner,
                get_nonce(&client, wallet.inner.address()).await,
                TxKind::Call(contract_addr),
                chain_id,
                ContractTestContext::get_is_odd_input_plaintext(),
            )
            .await,
        ),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let decrypted_output =
        client_decrypt(&wallet.inner, get_nonce(&client, wallet.inner.address()).await, &output)
            .await;
    println!("eth_call decrypted output: {:?}", decrypted_output);
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::from(1));

    let simulate_tx_request = get_unsigned_seismic_tx_request(
        &wallet.inner,
        get_nonce(&client, wallet.inner.address()).await,
        TxKind::Call(contract_addr),
        chain_id,
        ContractTestContext::get_is_odd_input_plaintext(),
    )
    .await;

    // test eth_estimateGas
    let gas = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::estimate_gas(
        &client,
        simulate_tx_request.clone(),
        None,
        None,
    )
    .await
    .unwrap();
    println!("eth_estimateGas for is_odd() gas: {:?}", gas);
    assert!(gas > U256::ZERO);

    let access_list =
        EthApiClient::<Transaction, Block, TransactionReceipt, Header>::create_access_list(
            &client,
            simulate_tx_request.clone(),
            None,
        )
        .await
        .unwrap();
    println!("eth_createAccessList for is_odd() access_list: {:?}", access_list);

    // test call
    let output = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::call(
        &client,
        reth_rpc_eth_api::types::SeismicCallRequest::TransactionRequest(
            simulate_tx_request.clone(),
        ),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    println!("eth_call is_odd() decrypted output: {:?}", output);

    // call with no transaction type
    let output = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::call(
        &client,
        reth_rpc_eth_api::types::SeismicCallRequest::TransactionRequest(
            alloy_rpc_types::TransactionRequest {
                from: Some(wallet.inner.address()),
                input: TransactionInput {
                    data: Some(ContractTestContext::get_is_odd_input_plaintext()),
                    ..Default::default()
                },
                to: Some(TxKind::Call(contract_addr)),
                ..Default::default()
            },
        ),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    println!("eth_call is_odd() with no transaction type decrypted output: {:?}", output);
}

async fn test_seismic_reth_backup() {
    let itx = IntegrationTestContext::load();
    let chain_id = DEV.chain;

    const RETH_RPC_URL: &str = "http://127.0.0.1:8545";

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
