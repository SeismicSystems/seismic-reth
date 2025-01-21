use alloy_consensus::{transaction::EncryptionPublicKey, TxSeismic};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex::{self, FromHex}, Address, PrimitiveSignature, B256, U256};
use assert_cmd::Command;
use reqwest::Client;
use reth_primitives::{Transaction, TransactionSigned};
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

    // Replay transaction, need to add right here, must be done before tx is mined.
    let replay_resp = replay_transaction(&client, RETH_RPC_URL, &itx.tx_hashes[0]).await.expect("Replay failed");
    println!("eth_call Response REPLAY ATTACK: {:?}", replay_resp);
    assert!(replay_resp["result"] == "0x");

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
}


async fn replay_transaction(
    client: &reqwest::Client,
    reth_rpc_url: &str,
    tx_hash: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    // Step 1: Get transaction by hash
    let get_transaction_hash = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    });

    let response: Value = client
        .post(reth_rpc_url)
        .json(&get_transaction_hash)
        .send()
        .await?
        .json()
        .await?;

    // Step 2: Generate signed transaction with the given fields
    let signed_tx = construct_transaction_signed(&response)
        .expect("Failed to construct signed transaction");
    let signed_call = signed_tx.encoded_2718();

    // Step 3: Replay transaction using eth_call
    let eth_call_replay = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [signed_call],
        "id": 1
    });

    let replay_response: Value = client
        .post(reth_rpc_url)
        .json(&eth_call_replay)
        .send()
        .await?
        .json()
        .await?;

    Ok(replay_response)
}

fn construct_transaction_signed(response: &Value) -> eyre::Result<TransactionSigned> {
    let nonce = u64::from_str_radix(response["result"]["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let gas_limit = u64::from_str_radix(response["result"]["gas"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let gas_price = u128::from_str_radix(response["result"]["gasPrice"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let value = U256::from_str_radix(response["result"]["value"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let input = hex::decode(response["result"]["input"].as_str().unwrap().trim_start_matches("0x"))?;
    let chain_id = u64::from_str_radix(response["result"]["chainId"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let encryption_pubkey: EncryptionPublicKey = alloy_primitives::FixedBytes::from_slice(
    hex::decode(response["result"]["encryptionPubkey"].as_str().unwrap().trim_start_matches("0x"))?.as_ref()
    );
    let tx_hash = B256::from_hex(response["result"]["hash"].as_str().unwrap())?;
    let to = if let Some(to) = response["result"]["to"].as_str() {
        Some(Address::from_str(to)?)
    } else {
        None
    };

    // extract signature components
    let r = U256::from_str(response["result"]["r"].as_str().unwrap())?;
    let s = U256::from_str(response["result"]["s"].as_str().unwrap())?;
    let v = match response["result"]["v"].as_str().unwrap() {
        "0x1" => true,
        "0x0" => false,
        _ => return Err(eyre::format_err!("Invalid v value")),
    };
    // construct the signature object
    let signature = PrimitiveSignature::new(r, s, v);

    // construct the transaction object
    let transaction = Transaction::Seismic(TxSeismic {
        nonce: nonce.into(),
        gas_price,
        gas_limit,
        to: to.into(),
        value,
        input: input.into(),
        chain_id,
        encryption_pubkey,
        ..Default::default()
    });

    let signed_tx = TransactionSigned::new(transaction, signature, tx_hash);

    Ok(signed_tx)
}
