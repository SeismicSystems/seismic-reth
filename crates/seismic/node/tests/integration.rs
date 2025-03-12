//! This file is used to test the seismic node.
use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_primitives::{
    aliases::{B96, U96},
    hex,
    hex::FromHex,
    Bytes, IntoLogData, TxKind, B256, U256,
};
use alloy_provider::{test_utils, Provider, SeismicSignedProvider, SendableTx};
use alloy_rpc_types::{
    Block, Header, Transaction, TransactionInput, TransactionReceipt, TransactionRequest,
};
use alloy_sol_types::{sol, SolCall, SolValue};
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_builder::engine_tree_config::DEFAULT_BACKUP_THRESHOLD;
use reth_rpc_eth_api::EthApiClient;
use seismic_enclave::aes_decrypt;
use seismic_node::utils::{
    test_utils::{
        client_decrypt, get_nonce, get_signed_seismic_tx_bytes, get_signed_seismic_tx_typed_data,
        get_unsigned_seismic_tx_request,
    },
    SeismicRethTestCommand,
};
use std::{path::PathBuf, thread, time::Duration};
use tokio::sync::mpsc;

const PRECOMPILES_TEST_SET_AES_KEY_SELECTOR: &str = "a0619040"; // setAESKey(suint256)
const PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR: &str = "28696e36"; // submitMessage(bytes)

#[tokio::test(flavor = "multi_thread")]
async fn integration_test() {
    let (tx, mut rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    SeismicRethTestCommand::run(tx, shutdown_rx).await;
    rx.recv().await.unwrap();

    test_seismic_reth_rpc_with_rust_client().await;
    test_seismic_reth_rpc().await;
    test_seismic_precompiles_end_to_end().await;
    test_seismic_reth_rpc_with_typed_data().await;

    let _ = shutdown_tx.try_send(()).unwrap();
    println!("shutdown signal sent");
    thread::sleep(Duration::from_secs(1));
}

async fn test_seismic_reth_rpc_with_typed_data() {
    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
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
}

// this is the same test as basic.rs but with actual RPC calls and standalone reth instance
// with rust client in alloy
async fn test_seismic_reth_rpc_with_rust_client() {
    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet = EthereumWallet::from(_wallet.inner);
    let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);

    let provider =
        SeismicSignedProvider::new(wallet.clone(), reqwest::Url::parse(&reth_rpc_url).unwrap());
    let pending_transaction = provider
        .send_transaction(
            TransactionRequest::default()
                .with_input(test_utils::ContractTestContext::get_deploy_input_plaintext())
                .with_kind(TxKind::Create)
                .with_from(address),
        )
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
        .seismic_call(SendableTx::Builder(
            TransactionRequest::default()
                .with_input(test_utils::ContractTestContext::get_is_odd_input_plaintext())
                .with_to(contract_addr)
                .with_from(address),
        ))
        .await
        .unwrap();
    println!("eth_call decrypted output: {:?}", output);
    assert_eq!(U256::from_be_slice(&output), U256::ZERO);

    // Send transaction to set suint
    let pending_transaction = provider
        .send_transaction(
            TransactionRequest::default()
                .with_input(test_utils::ContractTestContext::get_set_number_input_plaintext())
                .with_to(contract_addr)
                .with_from(address),
        )
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
        .seismic_call(SendableTx::Builder(
            TransactionRequest::default()
                .with_input(test_utils::ContractTestContext::get_is_odd_input_plaintext())
                .with_to(contract_addr)
                .with_from(address),
        ))
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
    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
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

async fn test_seismic_precompiles_end_to_end() {
    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet = EthereumWallet::from(_wallet.inner);
    let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);

    let provider =
        SeismicSignedProvider::new(wallet.clone(), reqwest::Url::parse(&reth_rpc_url).unwrap());
    let pending_transaction = provider
        .send_transaction(
            TransactionRequest::default()
                .with_input(get_encryption_precompiles_contracts())
                .with_kind(TxKind::Create)
                .with_from(address),
        )
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    assert_eq!(receipt.status(), true);

    let code = provider.get_code_at(contract_addr).await.unwrap();
    assert_eq!(get_runtime_code(), code);

    // Prepare addresses & keys
    let private_key =
        B256::from_hex("7e34abdcd62eade2e803e0a8123a0015ce542b380537eff288d6da420bcc2d3b").unwrap();

    //
    // 2. Tx #1: Set AES key in the contract
    //
    let unencrypted_aes_key = get_input_data(PRECOMPILES_TEST_SET_AES_KEY_SELECTOR, private_key);
    let pending_transaction = provider
        .send_transaction(
            TransactionRequest::default()
                .with_input(unencrypted_aes_key)
                .with_kind(TxKind::Call(contract_addr))
                .with_from(address),
        )
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    assert_eq!(receipt.status(), true);

    //
    // 3. Tx #2: Encrypt & send "hello world"
    //
    let raw_message = "hello world";
    let message = Bytes::from(raw_message);
    type PlaintextType = Bytes; // used for AbiEncode / AbiDecode

    let encoded_message = PlaintextType::abi_encode(&message);
    let unencrypted_input =
        concat_input_data(PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR, encoded_message.into());

    let pending_transaction = provider
        .send_transaction(
            TransactionRequest::default()
                .with_input(unencrypted_input)
                .with_kind(TxKind::Call(contract_addr))
                .with_from(address),
        )
        .await
        .unwrap();
    let tx_hash = pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

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
    let unencrypted_decrypt_call: Bytes = call.abi_encode().into();

    let decrypted_output = provider
        .seismic_call(SendableTx::Builder(
            TransactionRequest::default()
                .with_input(unencrypted_decrypt_call)
                .with_kind(TxKind::Call(contract_addr))
                .with_from(address),
        ))
        .await
        .unwrap();
    let result_bytes = PlaintextType::abi_decode(&Bytes::from(decrypted_output), false)
        .expect("failed to decode the bytes");
    let final_string =
        String::from_utf8(result_bytes.to_vec()).expect("invalid utf8 in decrypted bytes");
    assert_eq!(final_string, raw_message);

    // Local Decrypt
    let secp_private = secp256k1::SecretKey::from_slice(private_key.as_ref()).unwrap();
    let aes_key: &[u8; 32] = &secp_private.secret_bytes()[0..32].try_into().unwrap();
    let decrypted_locally =
        aes_decrypt(aes_key.into(), &ciphertext, decoded.indexed[0].abi_encode_packed())
            .expect("AES decryption failed");
    assert_eq!(decrypted_locally, message);
}

/// Get the deploy input plaintext
/// https://github.com/SeismicSystems/early-builds/blob/main/encrypted_logs/src/end-to-end-mvp/EncryptedLogs.sol
fn get_encryption_precompiles_contracts() -> Bytes {
    Bytes::from_static(&hex!("6080604052348015600e575f5ffd5b50335f5f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610dce8061005b5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806328696e361461004e5780638da5cb5b1461006a578063a061904014610088578063ce75255b146100a4575b5f5ffd5b61006860048036038101906100639190610687565b6100d4565b005b61007261019a565b60405161007f9190610711565b60405180910390f35b6100a2600480360381019061009d919061075d565b6101be565b005b6100be60048036038101906100b991906107c9565b610256565b6040516100cb9190610896565b60405180910390f35b5f6100dd610412565b90505f61012d8285858080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f820116905080830192505050505050506104f5565b9050816bffffffffffffffffffffffff167f093a34a48cc07b4bf1355d9c15ec71077c85342d872753188302f99341f961008260405160200161017091906108f0565b60405160208183030381529060405260405161018c9190610896565b60405180910390a250505050565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461024c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161024390610986565b60405180910390fd5b8060018190b15050565b60605f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146102e6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102dd90610986565b60405180910390fd5b5f838390501161032b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610322906109ee565b60405180910390fd5b5f606790505f6001b086868660405160200161034a9493929190610a92565b60405160208183030381529060405290505f5f8373ffffffffffffffffffffffffffffffffffffffff168360405161038291906108f0565b5f60405180830381855afa9150503d805f81146103ba576040519150601f19603f3d011682016040523d82523d5f602084013e6103bf565b606091505b509150915081610404576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103fb90610b3c565b60405180910390fd5b809450505050509392505050565b5f5f606490505f5f8273ffffffffffffffffffffffffffffffffffffffff1660206040516020016104439190610b9d565b60405160208183030381529060405260405161045f91906108f0565b5f60405180830381855afa9150503d805f8114610497576040519150601f19603f3d011682016040523d82523d5f602084013e61049c565b606091505b5091509150816104e1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104d890610c01565b60405180910390fd5b5f60208201519050805f1c94505050505090565b60605f606690505f6001b0858560405160200161051493929190610c1f565b60405160208183030381529060405290505f5f8373ffffffffffffffffffffffffffffffffffffffff168360405161054c91906108f0565b5f60405180830381855afa9150503d805f8114610584576040519150601f19603f3d011682016040523d82523d5f602084013e610589565b606091505b5091509150816105ce576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105c590610cc7565b60405180910390fd5b5f815111610611576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161060890610d55565b60405180910390fd5b8094505050505092915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261064757610646610626565b5b8235905067ffffffffffffffff8111156106645761066361062a565b5b6020830191508360018202830111156106805761067f61062e565b5b9250929050565b5f5f6020838503121561069d5761069c61061e565b5b5f83013567ffffffffffffffff8111156106ba576106b9610622565b5b6106c685828601610632565b92509250509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6106fb826106d2565b9050919050565b61070b816106f1565b82525050565b5f6020820190506107245f830184610702565b92915050565b5f819050919050565b61073c8161072a565b8114610746575f5ffd5b50565b5f8135905061075781610733565b92915050565b5f602082840312156107725761077161061e565b5b5f61077f84828501610749565b91505092915050565b5f6bffffffffffffffffffffffff82169050919050565b6107a881610788565b81146107b2575f5ffd5b50565b5f813590506107c38161079f565b92915050565b5f5f5f604084860312156107e0576107df61061e565b5b5f6107ed868287016107b5565b935050602084013567ffffffffffffffff81111561080e5761080d610622565b5b61081a86828701610632565b92509250509250925092565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f61086882610826565b6108728185610830565b9350610882818560208601610840565b61088b8161084e565b840191505092915050565b5f6020820190508181035f8301526108ae818461085e565b905092915050565b5f81905092915050565b5f6108ca82610826565b6108d481856108b6565b93506108e4818560208601610840565b80840191505092915050565b5f6108fb82846108c0565b915081905092915050565b5f82825260208201905092915050565b7f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f5f8201527f6e00000000000000000000000000000000000000000000000000000000000000602082015250565b5f610970602183610906565b915061097b82610916565b604082019050919050565b5f6020820190508181035f83015261099d81610964565b9050919050565b7f436970686572746578742063616e6e6f7420626520656d7074790000000000005f82015250565b5f6109d8601a83610906565b91506109e3826109a4565b602082019050919050565b5f6020820190508181035f830152610a05816109cc565b9050919050565b5f819050919050565b610a26610a218261072a565b610a0c565b82525050565b5f8160a01b9050919050565b5f610a4282610a2c565b9050919050565b610a5a610a5582610788565b610a38565b82525050565b828183375f83830152505050565b5f610a7983856108b6565b9350610a86838584610a60565b82840190509392505050565b5f610a9d8287610a15565b602082019150610aad8286610a49565b600c82019150610abe828486610a6e565b915081905095945050505050565b7f414553206465637279707420707265636f6d70696c652063616c6c206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610b26602283610906565b9150610b3182610acc565b604082019050919050565b5f6020820190508181035f830152610b5381610b1a565b9050919050565b5f63ffffffff82169050919050565b5f8160e01b9050919050565b5f610b7f82610b69565b9050919050565b610b97610b9282610b5a565b610b75565b82525050565b5f610ba88284610b86565b60048201915081905092915050565b7f524e4720507265636f6d70696c652063616c6c206661696c65640000000000005f82015250565b5f610beb601a83610906565b9150610bf682610bb7565b602082019050919050565b5f6020820190508181035f830152610c1881610bdf565b9050919050565b5f610c2a8286610a15565b602082019150610c3a8285610a49565b600c82019150610c4a82846108c0565b9150819050949350505050565b7f41455320656e637279707420707265636f6d70696c652063616c6c206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610cb1602283610906565b9150610cbc82610c57565b604082019050919050565b5f6020820190508181035f830152610cde81610ca5565b9050919050565b7f456e6372797074696f6e2063616c6c2072657475726e6564206e6f206f7574705f8201527f7574000000000000000000000000000000000000000000000000000000000000602082015250565b5f610d3f602283610906565b9150610d4a82610ce5565b604082019050919050565b5f6020820190508181035f830152610d6c81610d33565b905091905056fea2646970667358221220cdc3edd7891930a1ad58becbe2b3f7679ecfc78a3b1f8a803d4c381c8318287864736f6c637827302e382e32382d63692e323032342e31312e342b636f6d6d69742e32306261666332392e6d6f640058"))
}

fn get_runtime_code() -> Bytes {
    Bytes::from_static(&hex!("608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806328696e361461004e5780638da5cb5b1461006a578063a061904014610088578063ce75255b146100a4575b5f5ffd5b61006860048036038101906100639190610687565b6100d4565b005b61007261019a565b60405161007f9190610711565b60405180910390f35b6100a2600480360381019061009d919061075d565b6101be565b005b6100be60048036038101906100b991906107c9565b610256565b6040516100cb9190610896565b60405180910390f35b5f6100dd610412565b90505f61012d8285858080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f820116905080830192505050505050506104f5565b9050816bffffffffffffffffffffffff167f093a34a48cc07b4bf1355d9c15ec71077c85342d872753188302f99341f961008260405160200161017091906108f0565b60405160208183030381529060405260405161018c9190610896565b60405180910390a250505050565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461024c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161024390610986565b60405180910390fd5b8060018190b15050565b60605f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146102e6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102dd90610986565b60405180910390fd5b5f838390501161032b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610322906109ee565b60405180910390fd5b5f606790505f6001b086868660405160200161034a9493929190610a92565b60405160208183030381529060405290505f5f8373ffffffffffffffffffffffffffffffffffffffff168360405161038291906108f0565b5f60405180830381855afa9150503d805f81146103ba576040519150601f19603f3d011682016040523d82523d5f602084013e6103bf565b606091505b509150915081610404576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103fb90610b3c565b60405180910390fd5b809450505050509392505050565b5f5f606490505f5f8273ffffffffffffffffffffffffffffffffffffffff1660206040516020016104439190610b9d565b60405160208183030381529060405260405161045f91906108f0565b5f60405180830381855afa9150503d805f8114610497576040519150601f19603f3d011682016040523d82523d5f602084013e61049c565b606091505b5091509150816104e1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104d890610c01565b60405180910390fd5b5f60208201519050805f1c94505050505090565b60605f606690505f6001b0858560405160200161051493929190610c1f565b60405160208183030381529060405290505f5f8373ffffffffffffffffffffffffffffffffffffffff168360405161054c91906108f0565b5f60405180830381855afa9150503d805f8114610584576040519150601f19603f3d011682016040523d82523d5f602084013e610589565b606091505b5091509150816105ce576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105c590610cc7565b60405180910390fd5b5f815111610611576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161060890610d55565b60405180910390fd5b8094505050505092915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261064757610646610626565b5b8235905067ffffffffffffffff8111156106645761066361062a565b5b6020830191508360018202830111156106805761067f61062e565b5b9250929050565b5f5f6020838503121561069d5761069c61061e565b5b5f83013567ffffffffffffffff8111156106ba576106b9610622565b5b6106c685828601610632565b92509250509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6106fb826106d2565b9050919050565b61070b816106f1565b82525050565b5f6020820190506107245f830184610702565b92915050565b5f819050919050565b61073c8161072a565b8114610746575f5ffd5b50565b5f8135905061075781610733565b92915050565b5f602082840312156107725761077161061e565b5b5f61077f84828501610749565b91505092915050565b5f6bffffffffffffffffffffffff82169050919050565b6107a881610788565b81146107b2575f5ffd5b50565b5f813590506107c38161079f565b92915050565b5f5f5f604084860312156107e0576107df61061e565b5b5f6107ed868287016107b5565b935050602084013567ffffffffffffffff81111561080e5761080d610622565b5b61081a86828701610632565b92509250509250925092565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f61086882610826565b6108728185610830565b9350610882818560208601610840565b61088b8161084e565b840191505092915050565b5f6020820190508181035f8301526108ae818461085e565b905092915050565b5f81905092915050565b5f6108ca82610826565b6108d481856108b6565b93506108e4818560208601610840565b80840191505092915050565b5f6108fb82846108c0565b915081905092915050565b5f82825260208201905092915050565b7f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f5f8201527f6e00000000000000000000000000000000000000000000000000000000000000602082015250565b5f610970602183610906565b915061097b82610916565b604082019050919050565b5f6020820190508181035f83015261099d81610964565b9050919050565b7f436970686572746578742063616e6e6f7420626520656d7074790000000000005f82015250565b5f6109d8601a83610906565b91506109e3826109a4565b602082019050919050565b5f6020820190508181035f830152610a05816109cc565b9050919050565b5f819050919050565b610a26610a218261072a565b610a0c565b82525050565b5f8160a01b9050919050565b5f610a4282610a2c565b9050919050565b610a5a610a5582610788565b610a38565b82525050565b828183375f83830152505050565b5f610a7983856108b6565b9350610a86838584610a60565b82840190509392505050565b5f610a9d8287610a15565b602082019150610aad8286610a49565b600c82019150610abe828486610a6e565b915081905095945050505050565b7f414553206465637279707420707265636f6d70696c652063616c6c206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610b26602283610906565b9150610b3182610acc565b604082019050919050565b5f6020820190508181035f830152610b5381610b1a565b9050919050565b5f63ffffffff82169050919050565b5f8160e01b9050919050565b5f610b7f82610b69565b9050919050565b610b97610b9282610b5a565b610b75565b82525050565b5f610ba88284610b86565b60048201915081905092915050565b7f524e4720507265636f6d70696c652063616c6c206661696c65640000000000005f82015250565b5f610beb601a83610906565b9150610bf682610bb7565b602082019050919050565b5f6020820190508181035f830152610c1881610bdf565b9050919050565b5f610c2a8286610a15565b602082019150610c3a8285610a49565b600c82019150610c4a82846108c0565b9150819050949350505050565b7f41455320656e637279707420707265636f6d70696c652063616c6c206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610cb1602283610906565b9150610cbc82610c57565b604082019050919050565b5f6020820190508181035f830152610cde81610ca5565b9050919050565b7f456e6372797074696f6e2063616c6c2072657475726e6564206e6f206f7574705f8201527f7574000000000000000000000000000000000000000000000000000000000000602082015250565b5f610d3f602283610906565b9150610d4a82610ce5565b604082019050919050565b5f6020820190508181035f830152610d6c81610d33565b905091905056fea2646970667358221220cdc3edd7891930a1ad58becbe2b3f7679ecfc78a3b1f8a803d4c381c8318287864736f6c637827302e382e32382d63692e323032342e31312e342b636f6d6d69742e32306261666332392e6d6f640058"))
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
