use alloy_primitives::{hex, Signature, B256, U256};
use assert_cmd::Command;
use reqwest::Client;
use reth_node_core::primitives::Transaction;
use reth_primitives::TransactionSigned;
use seismic_node::utils::test_utils::IntegrationTestTx;
use serde_json::{json, Value};
use std::{str::FromStr, thread, time::Duration};
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
use tokio::process::Child;

struct RethCommand(Child);

impl RethCommand {
    fn run() -> RethCommand {
        let cmd = Command::cargo_bin("seismic-reth").unwrap();
        let cmd_str = cmd.get_program().to_str().unwrap();
        let child = tokio::process::Command::new(cmd_str)
            .arg("node")
            .arg("--datadir")
            .arg("./tmp/reth")
            .arg("--dev")
            .arg("--dev.block-max-transactions")
            .arg("1")
            .arg("--tee.mock-server")
            .arg("-vvvv")
            .spawn()
            .expect("Failed to start the binary");
        RethCommand(child)
    }
}

impl Drop for RethCommand {
    fn drop(&mut self) {
        // kill the process
        let pid = self.0.id().unwrap();
        if let Some(process) = System::new_all().process(Pid::from_u32(pid)) {
            process.kill();
        }
    }
}

// this is the same test as basic.rs but with actual RPC calls and standalone reth instance
#[tokio::test]
async fn test_seismic_reth_rpc() {
    let itx = IntegrationTestTx::load();

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
    println!("eth_call Response (parity 0): {:?}", response);
    assert!(
        response["result"] == "0x0000000000000000000000000000000000000000000000000000000000000000"
    );

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
    assert!(
        response["result"] == "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    println!("eth_call Response (parity 1): {:?}", response);

    // Step 6: Replay Transaction in step 3
    // get transction hash
    let get_transaction_hash = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [itx.tx_hashes[0]],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&get_transaction_hash)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");

    // Generate signed transaction with the given fields

    // Send signed transaction eth eth_call endpoint, unveiling suint without nonce checks

    println!("eth_getTransactionByHash Response: {:?}", response);
}

fn construct_transaction_signed(response: &Value) -> eyre::Result<TransactionSigned> {
    // Extract fields from the response
    let nonce = U256::from_str_radix(response["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let gas_price = U256::from_str_radix(response["gasPrice"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let gas = U256::from_str_radix(response["gas"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let value = U256::from_str_radix(response["value"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let input = hex::decode(response["input"].as_str().unwrap().trim_start_matches("0x"))?;
    let chain_id = U256::from_str_radix(response["chainId"].as_str().unwrap().trim_start_matches("0x"), 16)?;

    let to = if let Some(to) = response["to"].as_str() {
        Some(to.parse()?)
    } else {
        None
    };

    // Extract signature components
    let r_bytes = B256::from_str(response["r"].as_str().unwrap())?;
    let s_bytes = B256::from_str(response["s"].as_str().unwrap())?;
    let r = U256::from_be_bytes(r_bytes.0);
    let s = U256::from_be_bytes(s_bytes.0);
    let v = Some(response["v"].as_bool());

    // Construct the Signature object
    let signature = Signature::new(r, s, alloy_primitives::Parity::from(v));

    // Construct the Transaction object
    let transaction = Transaction {
        nonce,
        gas_price: Some(gas_price),
        gas_limit: gas,
        to,
        value,
        data: input.into(),
        chain_id: Some(chain_id.as_u64()),
        ..Default::default()
    };

    // Construct the TransactionSigned object
    let tx_signed = TransactionSigned {
        hash: OnceLock::new(),
        signature,
        transaction,
    };

    Ok(tx_signed)
}
