//! This file is used to test the seismic node.
use alloy_network::{Ethereum, EthereumWallet, NetworkWallet};
use alloy_primitives::aliases::{B96, U96};
use alloy_primitives::{hex::FromHex, Address, Bytes, FixedBytes, TxKind, B256, U256, IntoLogData};
use alloy_primitives::hex;
use alloy_provider::{create_seismic_provider, test_utils, Provider, SendableTx};
use alloy_rpc_types::{
    Block, Header, Transaction, TransactionInput, TransactionReceipt, TransactionRequest,
};
use assert_cmd::Command;
use reqwest::Client;
use reth_chainspec::DEV;
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_builder::engine_tree_config::DEFAULT_BACKUP_THRESHOLD;
use reth_rpc_eth_api::EthApiClient;
use seismic_node::utils::test_utils::{
    client_decrypt, get_nonce, get_signed_seismic_tx_bytes, get_signed_seismic_tx_typed_data,
    get_unsigned_seismic_tx_request, IntegrationTestContext,
};
use serde_json::{json, Value};
use tee_service_api::{get_sample_secp256k1_pk, get_sample_secp256k1_sk};
use std::{path::PathBuf, str::FromStr, thread, time::Duration};
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
use tokio::process::Child;
struct RethCommand(Child);
use alloy_sol_types::{sol, SolCall, SolValue};
use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};



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
            .arg("-vv")
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


pub const PRECOMPILES_TEST_SET_AES_KEY_SELECTOR: &str = "a0619040"; // setAESKey(suint256)
pub const PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR: &str = "28696e36"; // submitMessage(bytes)

#[tokio::test]
async fn integration_test() {
    let _cmd = RethCommand::run();
    thread::sleep(Duration::from_secs(5));

    test_seismic_reth_backup().await;
    test_seismic_reth_rpc_with_rust_client().await;
    test_seismic_reth_rpc().await;
    test_seismic_precompiles_end_to_end().await;
}

#[tokio::test]
async fn try_seismic_precompiles_end_to_end() {
    let _cmd = RethCommand::run();
    thread::sleep(Duration::from_secs(5));

    test_seismic_precompiles_end_to_end().await;
}
async fn test_seismic_reth_rpc_with_typed_data() {
    let reth_rpc_url = RethCommand::url();
    let chain_id = RethCommand::chain_id();
    let client = jsonrpsee::http_client::HttpClientBuilder::default().build(reth_rpc_url).unwrap();
    let wallet = Wallet::default().with_chain_id(chain_id);

    let tx_hash =
        EthApiClient::<Transaction, Block, TransactionReceipt, Header>::send_raw_transaction(
            &client,
            get_signed_seismic_tx_typed_data(
                &wallet.inner,
                get_nonce(&client, wallet.inner.address()).await,
                TxKind::Create,
                chain_id,
                test_utils::ContractTestContext::get_deploy_input_plaintext(),
            )
            .await
            .into(),
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
    assert_eq!(test_utils::ContractTestContext::get_code(), code);
    println!("eth_getCode getting contract deployment code: {:?}", code);

    // eth_call to check the parity. Should be 0
    let output = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::call(
        &client,
        get_signed_seismic_tx_typed_data(
            &wallet.inner,
            get_nonce(&client, wallet.inner.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            test_utils::ContractTestContext::get_is_odd_input_plaintext(),
        )
        .await
        .into(),
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
>>>>>>> origin/seismic
}

// this is the same test as basic.rs but with actual RPC calls and standalone reth instance
// with rust client in alloy
async fn test_seismic_reth_rpc_with_rust_client() {
    let reth_rpc_url = RethCommand::url();
    let chain_id = RethCommand::chain_id();
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet = EthereumWallet::from(_wallet.inner);
    let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);

    let provider =
        create_seismic_provider(wallet.clone(), reqwest::Url::parse(&reth_rpc_url).unwrap());
    let pending_transaction = provider
        .send_transaction(test_utils::get_seismic_tx_builder(
            test_utils::ContractTestContext::get_deploy_input_plaintext(),
            TxKind::Create,
            address,
        ))
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    // assert_eq!(tx_hash, itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));
    println!("eth_sendRawTransaction deploying contract tx_hash: {:?}", tx_hash);

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    println!(
        "eth_getTransactionReceipt getting contract deployment transaction receipt: {:?}",
        receipt
    );
    assert_eq!(receipt.status(), true);

    // Make sure the code of the contract is deployed
    let code = provider.get_code_at(contract_addr).await.unwrap();
    assert_eq!(test_utils::ContractTestContext::get_code(), code);
    println!("eth_getCode getting contract deployment code: {:?}", code);

    // eth_call to check the parity. Should be 0
    let output = provider
        .seismic_call(SendableTx::Builder(test_utils::get_seismic_tx_builder(
            test_utils::ContractTestContext::get_is_odd_input_plaintext(),
            TxKind::Call(contract_addr),
            address,
        )))
        .await
        .unwrap();
    println!("eth_call decrypted output: {:?}", output);
    assert_eq!(U256::from_be_slice(&output), U256::ZERO);

    // Send transaction to set suint
    let pending_transaction = provider
        .send_transaction(test_utils::get_seismic_tx_builder(
            test_utils::ContractTestContext::get_set_number_input_plaintext(),
            TxKind::Call(contract_addr),
            address,
        ))
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    println!("eth_sendRawTransaction setting number transaction tx_hash: {:?}", tx_hash);
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    println!("eth_getTransactionReceipt getting set_number transaction receipt: {:?}", receipt);
    assert_eq!(receipt.status(), true);

    // Final eth_call to check the parity. Should be 1
    let output = provider
        .seismic_call(SendableTx::Builder(test_utils::get_seismic_tx_builder(
            test_utils::ContractTestContext::get_is_odd_input_plaintext(),
            TxKind::Call(contract_addr),
            address,
        )))
        .await
        .unwrap();
    println!("eth_call decrypted output: {:?}", output);
    assert_eq!(U256::from_be_slice(&output), U256::from(1));

    // eth_estimateGas cannot be called directly with rust client
    // eth_createAccessList cannot be called directly with rust client
    // rust client also does not support Eip712::typed data requests
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
                test_utils::ContractTestContext::get_deploy_input_plaintext(),
            )
            .await
            .into(),
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
    assert_eq!(test_utils::ContractTestContext::get_code(), code);
    println!("eth_getCode getting contract deployment code: {:?}", code);

    // eth_call to check the parity. Should be 0
    let output = EthApiClient::<Transaction, Block, TransactionReceipt, Header>::call(
        &client,
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(&client, wallet.inner.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            test_utils::ContractTestContext::get_is_odd_input_plaintext(),
        )
        .await
        .into(),
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
                test_utils::ContractTestContext::get_set_number_input_plaintext(),
            )
            .await
            .into(),
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
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(&client, wallet.inner.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            test_utils::ContractTestContext::get_is_odd_input_plaintext(),
        )
        .await
        .into(),
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
        test_utils::ContractTestContext::get_is_odd_input_plaintext(),
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
        simulate_tx_request.clone().into(),
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
        TransactionRequest {
            from: Some(wallet.inner.address()),
            input: TransactionInput {
                data: Some(test_utils::ContractTestContext::get_is_odd_input_plaintext()),
                ..Default::default()
            },
            to: Some(TxKind::Call(contract_addr)),
            ..Default::default()
        }
        .into(),
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

async fn test_seismic_precompiles_end_to_end() {
    let reth_rpc_url = RethCommand::url();
    let chain_id = RethCommand::chain_id();
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet = EthereumWallet::from(_wallet.inner);
    let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);

    let provider =
        create_seismic_provider(wallet.clone(), reqwest::Url::parse(&reth_rpc_url).unwrap());
    let pending_transaction = provider
        .send_transaction(test_utils::get_seismic_tx_builder(
            get_encryption_precompiles_contracts(),
            TxKind::Create,
            address,
        ))
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    // assert_eq!(tx_hash, itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));
    println!("eth_sendRawTransaction deploying contract tx_hash: {:?}", tx_hash);

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    println!(
        "eth_getTransactionReceipt getting contract deployment transaction receipt: {:?}",
        receipt
    );
    assert_eq!(receipt.status(), true);

    // Prepare addresses & keys
    let encryption_sk = get_sample_secp256k1_sk();
    let encryption_pk = Bytes::from(get_sample_secp256k1_pk().serialize());
    let encryption_pk_write_tx = FixedBytes::<33>::from(get_sample_secp256k1_pk().serialize());
    let private_key =
        B256::from_hex("7e34abdcd62eade2e803e0a8123a0015ce542b380537eff288d6da420bcc2d3b").unwrap();

    //
    // 2. Tx #1: Set AES key in the contract
    //
    let unencrypted_aes_key = get_input_data(PRECOMPILES_TEST_SET_AES_KEY_SELECTOR, private_key);
    let pending_transaction = provider
        .send_transaction(test_utils::get_seismic_tx_builder(
            unencrypted_aes_key,
            TxKind::Call(contract_addr),
            address,
        ))
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    // assert_eq!(tx_hash, itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));
    println!("eth_sendRawTransaction deploying contract tx_hash: {:?}", tx_hash);

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    assert_eq!(receipt.status(), true);

    //
    // 3. Tx #2: Encrypt & send "hello world"
    //
    let message = Bytes::from("hello world");
    type PlaintextType = Bytes; // used for AbiEncode / AbiDecode

    let encoded_message = PlaintextType::abi_encode(&message);
    let unencrypted_input =
        concat_input_data(PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR, encoded_message.into());

    let pending_transaction = provider
        .send_transaction(test_utils::get_seismic_tx_builder(
            unencrypted_input,
            TxKind::Call(contract_addr),
            address,
        ))
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    // assert_eq!(tx_hash, itx.tx_hashes[0]);
    thread::sleep(Duration::from_secs(1));
    println!("eth_sendRawTransaction deploying contract tx_hash: {:?}", tx_hash);

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    assert_eq!(receipt.status(), true);

    //
    // 4. Tx #3: On-chain decrypt
    //
    let logs = receipt.inner.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].inner.address, contract_addr);

    // Decode the EncryptedMessage event
    let log_data = logs[0].inner.data.clone();
    let event = Event {
        name: "EncryptedMessage".into(),
        inputs: vec![
            EventParam { ty: "int96".into(), indexed: true, ..Default::default() },
            EventParam { ty: "bytes".into(), indexed: false, ..Default::default() },
        ],
        anonymous: false,
    };
    let decoded = event.decode_log(&log_data.into_log_data(), false).unwrap();

    sol! {
        #[derive(Debug, PartialEq)]
        interface Encryption {
            function decrypt(uint96 nonce, bytes calldata ciphertext)
                external
                view
                onlyOwner
                returns (bytes memory plaintext);
        }
    }

    // Extract (nonce, ciphertext)
    let nonce: U96 =
        U96::from_be_bytes(B96::from_slice(&decoded.indexed[0].abi_encode_packed()).into());
    let ciphertext = Bytes::from(decoded.body[0].abi_encode_packed());

    let call = Encryption::decryptCall { nonce, ciphertext: ciphertext.clone() };
    let unencrypted_decrypt_call = call.abi_encode();

    let output = provider
        .seismic_call(SendableTx::Builder(test_utils::get_seismic_tx_builder(
            unencrypted_decrypt_call.into(),
            TxKind::Call(contract_addr),
            address,
        )))
        .await
        .unwrap();
    println!("eth_call decrypted output: {:?}", output);
}

/// Get the deploy input plaintext
/// https://github.com/SeismicSystems/early-builds/blob/main/encrypted_logs/src/end-to-end-mvp/EncryptedLogs.sol
fn get_encryption_precompiles_contracts() -> Bytes {
    Bytes::from_static(&hex!("60806040525f5f8190b150610285806100175f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806324a7f0b71461004357806343bd0d701461005f578063d09de08a1461007d575b5f5ffd5b61005d600480360381019061005891906100f6565b610087565b005b610067610090565b604051610074919061013b565b60405180910390f35b6100856100a7565b005b805f8190b15050565b5f600160025fb06100a19190610181565b14905090565b5f5f81b0809291906100b8906101de565b919050b150565b5f5ffd5b5f819050919050565b6100d5816100c3565b81146100df575f5ffd5b50565b5f813590506100f0816100cc565b92915050565b5f6020828403121561010b5761010a6100bf565b5b5f610118848285016100e2565b91505092915050565b5f8115159050919050565b61013581610121565b82525050565b5f60208201905061014e5f83018461012c565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61018b826100c3565b9150610196836100c3565b9250826101a6576101a5610154565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101e8826100c3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361021a576102196101b1565b5b60018201905091905056fea2646970667358221220ea421d58b6748a9089335034d76eb2f01bceafe3dfac2e57d9d2e766852904df64736f6c63782c302e382e32382d646576656c6f702e323032342e31322e392b636f6d6d69742e39383863313261662e6d6f64005d"))
}

/// Gets the input data for a given selector function and one B256 value
fn get_input_data(selector: &str, value: B256) -> Bytes {
    let selector_bytes: Vec<u8> = hex::decode(&selector[0..8]).expect("Invalid selector");

    // Convert value to bytes
    let value_bytes: Bytes = value.into();

    // Initialize the input data with the selector and value
    let mut input_data = Vec::new();
    input_data.extend_from_slice(&selector_bytes);
    input_data.extend_from_slice(&value_bytes);

    input_data.into()
}

fn concat_input_data(selector: &str, value: Bytes) -> Bytes {
    let selector_bytes: Vec<u8> = hex::decode(&selector[0..8]).expect("Invalid selector");

    // Convert value to bytes
    let value_bytes: Bytes = value.into();

    // Initialize the input data with the selector and value
    let mut input_data = Vec::new();
    input_data.extend_from_slice(&selector_bytes);
    input_data.extend_from_slice(&value_bytes);

    input_data.into()
}
