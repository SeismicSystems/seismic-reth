//! Integration tests for the Seismic node RPC.
//!
//! Each test spawns its own in-process Seismic node via `setup(1)`, eliminating
//! the previous subprocess-based approach (`cargo run --bin seismic-reth`).
//! Blocks are produced explicitly via `node.advance_block()` instead of relying
//! on dev-mode auto-mining with `thread::sleep`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)] // Test file - panics are acceptable

use alloy_consensus::TxEnvelope;
use alloy_dyn_abi::EventExt;
use alloy_eips::eip2718::Encodable2718;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{EthereumWallet, ReceiptResponse, TransactionBuilder};
use alloy_primitives::{
    aliases::{B96, U96},
    hex,
    hex::FromHex,
    Address, Bytes, IntoLogData, TxKind, B256, U256,
};
use alloy_provider::{Provider, SendableTx};
use alloy_rpc_types::{
    state::{AccountOverride, StateOverride},
    Block, Header, TransactionInput, TransactionRequest,
};
use alloy_rpc_types_eth::Bundle;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall, SolValue};
use core::str::FromStr;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_e2e_test_utils::wallet::Wallet;
use reth_rpc_eth_api::EthApiClient;
use reth_seismic_node::utils::{
    e2e::{ensure_mock_purpose_keys, setup, SeismicTestNode},
    test_utils::{
        client_decrypt, get_nonce, get_plaintext, get_seismic_metadata,
        get_signed_seismic_tx_bytes, get_signed_seismic_tx_typed_data,
        get_unsigned_seismic_tx_request,
    },
};
use reth_seismic_primitives::{
    test_utils::{get_unsigned_legacy_tx_request, sign_tx},
    SeismicBlock, SeismicTransactionSigned,
};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use seismic_alloy_consensus::SeismicTxEnvelope;
use seismic_alloy_network::{
    reth::builder::seismic_reth_tx_builder, wallet::SeismicWallet, SeismicReth,
};
use seismic_alloy_provider::{
    test_utils::ContractTestContext, SeismicProviderBuilder, SignedProviderExt,
};
use seismic_alloy_rpc_types::{
    SeismicCallRequest, SeismicTransactionReceipt, SeismicTransactionRequest, SimBlock,
    SimulatePayload,
};
use seismic_enclave::aes_decrypt;

const PRECOMPILES_TEST_SET_AES_KEY_SELECTOR: &str = "a0619040"; // setAESKey(suint256)
const PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR: &str = "28696e36"; // submitMessage(bytes)

/// Helper function to get a recent block hash from the client
async fn get_recent_block_hash(client: &jsonrpsee::http_client::HttpClient) -> B256 {
    let result: serde_json::Value = client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .expect("Failed to get latest block");

    let hash_str = result["hash"].as_str().expect("Block hash not found in response");

    B256::from_str(hash_str).expect("Failed to parse block hash")
}

/// Helper function to create a regular (non-seismic) deployment transaction
async fn get_signed_deploy_tx_bytes(
    wallet: impl Into<EthereumWallet> + Clone,
    nonce: u64,
    chain_id: u64,
    deploy_bytecode: Bytes,
) -> Bytes {
    let tx = TransactionRequest {
        from: None,
        to: Some(TxKind::Create),
        gas: Some(6000000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(1e9 as u128),
        value: Some(U256::ZERO),
        input: TransactionInput { input: Some(deploy_bytecode), data: None },
        nonce: Some(nonce),
        chain_id: Some(chain_id),
        ..Default::default()
    };

    let eth_wallet: EthereumWallet = wallet.into();
    let tx_envelope = tx.build(&eth_wallet).await.expect("Failed to build transaction");

    TxEnvelope::encoded_2718(&tx_envelope).into()
}

/// Sets up a single in-process Seismic node for testing and returns the node,
/// an HTTP RPC client, `chain_id`, wallet, and task manager.
///
/// The `TaskManager` must be held alive for the test duration — dropping it
/// cancels background tasks that power the node.
async fn setup_test_node() -> eyre::Result<(
    SeismicTestNode,
    jsonrpsee::http_client::HttpClient,
    u64,
    Wallet,
    reth_tasks::TaskManager,
)> {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();
    // Spawn node setup on a separate task to move the large async state machine
    // (node + engine + RPC + EVM) onto the heap, avoiding stack overflow on
    // x86_64 CI where stack frames are larger than on ARM64.
    let (mut nodes, tasks, wallet) =
        tokio::spawn(setup(1)).await.expect("node setup task panicked")?;
    let node = nodes.pop().unwrap();
    let rpc_url = node.rpc_url().to_string();
    let chain_id = wallet.chain_id;
    let client = HttpClientBuilder::default().build(&rpc_url)?;
    Ok((node, client, chain_id, wallet, tasks))
}

/// Deploy contract, verify receipt and code, then return the contract address + block hash.
async fn rpc_test_deploy_contract(
    node: &mut SeismicTestNode,
    client: &jsonrpsee::http_client::HttpClient,
    chain_id: u64,
    wallet: &Wallet,
) -> eyre::Result<(alloy_primitives::Address, B256)> {
    let tx_hash = EthApiOverrideClient::<Block>::send_raw_transaction(
        client,
        get_signed_deploy_tx_bytes(
            wallet.inner.clone(),
            get_nonce(client, wallet.inner.address()).await,
            chain_id,
            ContractTestContext::get_deploy_input_plaintext(),
        )
        .await
        .into(),
    )
    .await
    .unwrap();
    node.advance_block().await?;

    let receipt = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::transaction_receipt(client, tx_hash)
    .await
    .unwrap()
    .unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    assert!(receipt.status());

    let code = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::get_code(client, contract_addr, None)
    .await
    .unwrap();
    assert_eq!(ContractTestContext::get_code(), code);

    let recent_block_hash = get_recent_block_hash(client).await;
    Ok((contract_addr, recent_block_hash))
}

/// Verify parity via encrypted `eth_call`, returning the decrypted result as `U256`.
async fn rpc_test_check_parity(
    client: &jsonrpsee::http_client::HttpClient,
    chain_id: u64,
    wallet: &Wallet,
    contract_addr: alloy_primitives::Address,
    recent_block_hash: B256,
) -> eyre::Result<U256> {
    let nonce = get_nonce(client, wallet.inner.address()).await;
    let to = TxKind::Call(contract_addr);
    let output = EthApiOverrideClient::<Block>::call(
        client,
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            nonce,
            to,
            chain_id,
            ContractTestContext::get_is_odd_input_plaintext(),
            recent_block_hash,
        )
        .await
        .into(),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let metadata = get_seismic_metadata(
        wallet.inner.address(),
        chain_id,
        nonce,
        to,
        U256::ZERO,
        recent_block_hash,
    );
    let decrypted = client_decrypt(metadata, &output).unwrap();
    Ok(U256::from_be_slice(&decrypted))
}

/// Send `set_number` transaction and advance block.
async fn rpc_test_set_number(
    node: &mut SeismicTestNode,
    client: &jsonrpsee::http_client::HttpClient,
    chain_id: u64,
    wallet: &Wallet,
    contract_addr: alloy_primitives::Address,
    recent_block_hash: B256,
) -> eyre::Result<()> {
    let tx_hash = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::send_raw_transaction(
        client,
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(client, wallet.inner.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            ContractTestContext::get_set_number_input_plaintext(),
            recent_block_hash,
        )
        .await,
    )
    .await
    .unwrap();
    node.advance_block().await?;

    let receipt = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::transaction_receipt(client, tx_hash)
    .await
    .unwrap()
    .unwrap();
    assert!(receipt.status());
    Ok(())
}

/// Test estimateGas, legacy call, and no-type call.
async fn rpc_test_gas_and_call_variants(
    client: &jsonrpsee::http_client::HttpClient,
    chain_id: u64,
    wallet: &Wallet,
    contract_addr: alloy_primitives::Address,
    recent_block_hash: B256,
) -> eyre::Result<()> {
    let simulate_tx_request = get_unsigned_seismic_tx_request(
        &wallet.inner,
        get_nonce(client, wallet.inner.address()).await,
        TxKind::Call(contract_addr),
        chain_id,
        ContractTestContext::get_is_odd_input_plaintext(),
        recent_block_hash,
    )
    .await;

    // test eth_estimateGas with signed bytes (unsigned requests have `from` sanitized)
    let gas = EthApiOverrideClient::<Block>::estimate_gas(
        client,
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(client, wallet.inner.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            ContractTestContext::get_is_odd_input_plaintext(),
            recent_block_hash,
        )
        .await
        .into(),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(gas > U256::ZERO);

    // Regression test for the stablecoin-gas allowance gap. PR #378 routed
    // eth_getBalance through max(native, usdc_balance) but `caller_gas_allowance`
    // (used by eth_estimateGas) still reads only native. A wallet with 0 native
    // and nonzero USDC must still get a >0 allowance.
    //
    // Fixture: anvil acct #6, allocated in dev.json with 0 native and 1000 USDC
    // at the predeploy's `_balances[addr]` storage slot.
    let usdc_only_signer: PrivateKeySigner =
        "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e".parse().unwrap();
    let usdc_gas = EthApiOverrideClient::<Block>::estimate_gas(
        client,
        get_signed_seismic_tx_bytes(
            &usdc_only_signer,
            get_nonce(client, usdc_only_signer.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            ContractTestContext::get_is_odd_input_plaintext(),
            recent_block_hash,
        )
        .await
        .into(),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(
        usdc_gas > U256::ZERO,
        "eth_estimateGas must honor USDC balance for caller_gas_allowance \
         (got 0 allowance for a USDC-only wallet)"
    );

    // eth_getAccountInfo is wallet-facing, so it reports the effective (USDC-inclusive)
    // balance, consistent with eth_getBalance. eth_getAccount mirrors the raw trie record
    // and must agree with eth_getProof, so it stays on the native balance. The
    // usdc_only_signer has 0 native and 1000 USDC.
    let usdc_addr = usdc_only_signer.address();
    let account_info = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::get_account_info(client, usdc_addr, alloy_eips::BlockId::latest())
    .await
    .unwrap();
    let get_balance = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::balance(client, usdc_addr, None)
    .await
    .unwrap();
    assert!(
        account_info.balance > U256::ZERO,
        "eth_getAccountInfo must report the effective USDC-inclusive balance"
    );
    assert_eq!(
        account_info.balance, get_balance,
        "eth_getAccountInfo balance must match eth_getBalance"
    );

    // eth_getAccount must NOT substitute the effective balance: it is either absent (the
    // account has no native presence) or reports the raw native balance (0 here).
    let raw_account = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::get_account(client, usdc_addr, alloy_eips::BlockId::latest())
    .await
    .unwrap();
    assert!(
        raw_account.is_none_or(|a| a.balance == U256::ZERO),
        "eth_getAccount must keep the raw native balance, not the effective USDC balance"
    );

    // test eth_estimateGas sanitizes unsigned seismic requests (clears `from` and
    // seismic_elements to prevent caller spoofing, same as eth_call)
    let unsigned_seismic_result = EthApiOverrideClient::<Block>::estimate_gas(
        client,
        SeismicCallRequest::TransactionRequest(simulate_tx_request.clone()),
        None,
        None,
    )
    .await;
    // Sanitized request simulates ciphertext as address(0) — expected to fail
    assert!(
        unsigned_seismic_result.is_err(),
        "unsigned seismic estimateGas should fail after sanitization"
    );

    // test eth_estimateGas works for plain unsigned requests (standard Ethereum behavior)
    let plain_unsigned_result = EthApiOverrideClient::<Block>::estimate_gas(
        client,
        SeismicCallRequest::TransactionRequest(SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput {
                    data: Some(ContractTestContext::get_is_odd_input_plaintext()),
                    ..Default::default()
                },
                ..Default::default()
            },
            seismic_elements: None,
        }),
        None,
        None,
    )
    .await
    .unwrap();
    println!("eth_estimateGas for plain unsigned is_odd() gas: {:?}", plain_unsigned_result);
    assert!(plain_unsigned_result > U256::ZERO);

    // NB: eth_createAccessList is intentionally not exercised here — it is disabled on Seismic
    // as a state-introspection side channel (see node.rs and test_create_access_list_disabled).

    let is_odd_tx_request = get_unsigned_legacy_tx_request(
        &wallet.inner,
        get_nonce(client, wallet.inner.address()).await,
        TxKind::Call(contract_addr),
        chain_id,
        ContractTestContext::get_is_odd_input_plaintext(),
    )
    .await;

    let _output = EthApiOverrideClient::<Block>::call(
        client,
        is_odd_tx_request.clone().into(),
        None,
        None,
        None,
    )
    .await
    .unwrap();

    // call with no transaction type
    let _output = EthApiOverrideClient::<Block>::call(
        client,
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                input: TransactionInput {
                    data: Some(ContractTestContext::get_is_odd_input_plaintext()),
                    ..Default::default()
                },
                to: Some(TxKind::Call(contract_addr)),
                ..Default::default()
            },
            seismic_elements: None,
        }
        .into(),
        None,
        None,
        None,
    )
    .await
    .unwrap();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_reth_rpc() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let (contract_addr, recent_block_hash) =
        rpc_test_deploy_contract(&mut node, &client, chain_id, &wallet).await?;

    // parity should be 0 before set_number
    let parity =
        rpc_test_check_parity(&client, chain_id, &wallet, contract_addr, recent_block_hash).await?;
    assert_eq!(parity, U256::ZERO);

    rpc_test_set_number(&mut node, &client, chain_id, &wallet, contract_addr, recent_block_hash)
        .await?;

    // parity should be 1 after set_number
    let parity =
        rpc_test_check_parity(&client, chain_id, &wallet, contract_addr, recent_block_hash).await?;
    assert_eq!(parity, U256::from(1));

    rpc_test_gas_and_call_variants(&client, chain_id, &wallet, contract_addr, recent_block_hash)
        .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_reth_rpc_with_typed_data() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let (contract_addr, recent_block_hash) =
        rpc_test_deploy_contract(&mut node, &client, chain_id, &wallet).await?;

    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let to = TxKind::Call(contract_addr);
    let output = EthApiOverrideClient::<Block>::call(
        &client,
        get_signed_seismic_tx_typed_data(
            &wallet.inner,
            nonce,
            to,
            chain_id,
            ContractTestContext::get_is_odd_input_plaintext(),
            recent_block_hash,
        )
        .await
        .into(),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let metadata = get_seismic_metadata(
        wallet.inner.address(),
        chain_id,
        nonce,
        to,
        U256::ZERO,
        recent_block_hash,
    );
    let decrypted_output = client_decrypt(metadata, &output).unwrap();
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::ZERO);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_reth_rpc_with_rust_client() -> eyre::Result<()> {
    let (mut node, _client, chain_id, _wallet, _tasks) = setup_test_node().await?;
    let reth_rpc_url = node.rpc_url().to_string();

    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet: SeismicWallet<SeismicReth> = SeismicWallet::from(_wallet.inner);

    let provider = SeismicProviderBuilder::new()
        .wallet(wallet)
        .connect_http(reqwest::Url::parse(&reth_rpc_url).unwrap())
        .await
        .unwrap();

    let req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            ContractTestContext::get_deploy_input_plaintext(),
        ),
        TxKind::Create,
    );
    let pending_transaction = provider.send_transaction(req).await.unwrap();
    let tx_hash = *pending_transaction.tx_hash();
    node.advance_block().await?;

    let receipt = provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    assert!(receipt.status());

    let code = provider.get_code_at(contract_addr).await.unwrap();
    assert_eq!(ContractTestContext::get_code(), code);

    let output = provider
        .seismic_call_raw(SendableTx::Builder(TransactionBuilder::<SeismicReth>::with_to(
            TransactionBuilder::<SeismicReth>::with_input(
                SeismicTransactionRequest::default(),
                ContractTestContext::get_is_odd_input_plaintext(),
            ),
            contract_addr,
        )))
        .await
        .unwrap();
    assert_eq!(U256::from_be_slice(&output), U256::ZERO);

    let set_num_tx = seismic_reth_tx_builder()
        .with_input(ContractTestContext::get_set_number_input_plaintext())
        .with_to(contract_addr)
        .into();
    let pending_transaction = provider.send_transaction(set_num_tx).await.unwrap();
    let tx_hash = *pending_transaction.tx_hash();
    node.advance_block().await?;

    let receipt = provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap();
    assert!(receipt.status());

    let output = provider
        .seismic_call_raw(SendableTx::Builder(TransactionBuilder::<SeismicReth>::with_to(
            TransactionBuilder::<SeismicReth>::with_input(
                SeismicTransactionRequest::default(),
                ContractTestContext::get_is_odd_input_plaintext(),
            ),
            contract_addr,
        )))
        .await
        .unwrap();
    assert_eq!(U256::from_be_slice(&output), U256::from(1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_precompiles_end_to_end() -> eyre::Result<()> {
    let (mut node, _client, chain_id, _wallet, _tasks) = setup_test_node().await?;
    let reth_rpc_url = node.rpc_url().to_string();

    let _wallet = Wallet::default().with_chain_id(chain_id);
    let from = _wallet.inner.address();
    let wallet: SeismicWallet<SeismicReth> = SeismicWallet::from(_wallet.inner);

    let provider = SeismicProviderBuilder::new()
        .wallet(wallet)
        .connect_http(reqwest::Url::parse(&reth_rpc_url).unwrap())
        .await
        .unwrap();
    let req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            get_encryption_precompiles_contracts(),
        ),
        TxKind::Create,
    );
    let pending_transaction = provider.send_transaction(req).await.unwrap();
    let tx_hash = *pending_transaction.tx_hash();
    node.advance_block().await?;

    let receipt = provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    assert!(receipt.status());

    let code = provider.get_code_at(contract_addr).await.unwrap();
    assert!(!code.is_empty(), "contract should have runtime code after deployment");

    let private_key =
        B256::from_hex("7e34abdcd62eade2e803e0a8123a0015ce542b380537eff288d6da420bcc2d3b").unwrap();

    // Tx #1: Set AES key in the contract
    let unencrypted_aes_key = get_input_data(PRECOMPILES_TEST_SET_AES_KEY_SELECTOR, private_key);
    let pending = provider
        .send_transaction(
            seismic_reth_tx_builder()
                .with_from(from)
                .with_to(contract_addr)
                .with_input(unencrypted_aes_key)
                .into(),
        )
        .await
        .unwrap();
    let set_key_tx_hash = *pending.tx_hash();
    node.advance_block().await?;
    let receipt = provider.get_transaction_receipt(set_key_tx_hash).await.unwrap().unwrap();
    assert!(receipt.status());

    // Tx #2: Encrypt & send "hello world"
    let raw_message = "hello world";
    let message = Bytes::from(raw_message);
    type PlaintextType = Bytes;

    let encoded_message = PlaintextType::abi_encode(&message);
    let unencrypted_input =
        concat_input_data(PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR, encoded_message.into());

    let pending = provider
        .send_transaction(
            seismic_reth_tx_builder()
                .with_from(from)
                .with_to(contract_addr)
                .with_input(unencrypted_input)
                .into(),
        )
        .await
        .unwrap();
    let encrypt_tx_hash = *pending.tx_hash();
    node.advance_block().await?;
    let receipt = provider.get_transaction_receipt(encrypt_tx_hash).await.unwrap().unwrap();

    // Verify the encrypted log event
    let logs = receipt.inner.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].inner.address, contract_addr);

    let log_data = logs[0].inner.data.clone();
    let event = Event {
        name: "EncryptedMessage".into(),
        inputs: vec![
            EventParam { ty: "uint96".into(), indexed: true, ..Default::default() },
            EventParam { ty: "bytes".into(), indexed: false, ..Default::default() },
        ],
        anonymous: false,
    };
    let decoded = event.decode_log(&log_data.into_log_data()).unwrap();

    sol! {
        #[derive(Debug, PartialEq, Eq)]
        interface Encryption {
            function decrypt(uint96 nonce, bytes calldata ciphertext)
                external
                view
                onlyOwner
                returns (bytes memory plaintext);
        }
    }

    let nonce: U96 =
        U96::from_be_bytes(B96::from_slice(&decoded.indexed[0].abi_encode_packed()).into());
    let ciphertext = Bytes::from(decoded.body[0].abi_encode_packed());

    let call = Encryption::decryptCall { nonce, ciphertext: ciphertext.clone() };
    let unencrypted_decrypt_call = Bytes::from(call.abi_encode());

    let tx_req = seismic_reth_tx_builder()
        .with_from(from)
        .with_to(contract_addr)
        .with_input(unencrypted_decrypt_call)
        .into()
        .seismic();

    let output = provider.seismic_call_raw(SendableTx::Builder(tx_req)).await.unwrap();

    // Locally decrypt to cross-check
    let secp_private = secp256k1::SecretKey::from_slice(private_key.as_ref()).unwrap();
    let aes_key: &[u8; 32] = &secp_private.secret_bytes()[0..32].try_into().unwrap();
    let nonce: [u8; 12] = decoded.indexed[0].abi_encode_packed().try_into().unwrap();
    let decrypted_locally =
        aes_decrypt(aes_key.into(), &ciphertext, nonce).expect("AES decryption failed");
    assert_eq!(decrypted_locally, message);

    let result_bytes = PlaintextType::abi_decode(&output).expect("failed to decode the bytes");
    let final_string =
        String::from_utf8(result_bytes.to_vec()).expect("invalid utf8 in decrypted bytes");
    assert_eq!(final_string, raw_message);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_rejects_sload_on_private_storage() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PRIVATE,
        U256::from(42),
    )
    .await?;

    // Raw SLOAD on private storage via eth_call - should FAIL
    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PRIVATE_SLOAD_RAW).unwrap().into();
    let result = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput { data: Some(read_calldata), ..Default::default() },
                ..Default::default()
            },
            seismic_elements: None,
        }
        .into(),
        None,
        None,
        None,
    )
    .await;

    match &result {
        Ok(output) => panic!("SLOAD on private storage should fail, but got Ok: {:?}", output),
        Err(e) => {
            let err_msg = e.to_string().to_lowercase();
            assert!(
                err_msg.contains("invalidprivatestorageaccess"),
                "Expected 'InvalidPrivateStorageAccess' revert, got: {}",
                err_msg
            );
        }
    }

    Ok(())
}

/// Deploy flagged storage contract and write a value, returning contract address.
async fn flagged_storage_deploy_and_write(
    node: &mut SeismicTestNode,
    client: &jsonrpsee::http_client::HttpClient,
    chain_id: u64,
    wallet: &Wallet,
    selector: &str,
    value: U256,
) -> eyre::Result<alloy_primitives::Address> {
    let tx_hash = EthApiOverrideClient::<Block>::send_raw_transaction(
        client,
        get_signed_deploy_tx_bytes(
            wallet.inner.clone(),
            get_nonce(client, wallet.inner.address()).await,
            chain_id,
            Bytes::from_static(FLAGGED_STORAGE_TEST_BYTECODE),
        )
        .await
        .into(),
    )
    .await
    .unwrap();
    node.advance_block().await?;

    let receipt = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::transaction_receipt(client, tx_hash)
    .await
    .unwrap()
    .unwrap();
    let contract_addr = receipt.contract_address.unwrap();
    assert!(receipt.status());

    // Write value via seismic tx
    let block_hash = get_recent_block_hash(client).await;
    let set_data = get_input_data(selector, B256::from(value));
    EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::send_raw_transaction(
        client,
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            get_nonce(client, wallet.inner.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            set_data,
            block_hash,
        )
        .await,
    )
    .await
    .unwrap();
    node.advance_block().await?;

    Ok(contract_addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_allows_cload_on_public_storage() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PUBLIC,
        U256::from(123),
    )
    .await?;

    let block_hash = get_recent_block_hash(&client).await;
    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PUBLIC_CLOAD).unwrap().into();
    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let result = EthApiOverrideClient::<Block>::call(
        &client,
        get_signed_seismic_tx_bytes(
            &wallet.inner,
            nonce,
            TxKind::Call(contract_addr),
            chain_id,
            read_calldata,
            block_hash,
        )
        .await
        .into(),
        None,
        None,
        None,
    )
    .await;

    assert!(result.is_ok(), "CLOAD on public storage should succeed, got: {:?}", result.err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_allows_cload_on_private_storage() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PRIVATE,
        U256::from(42),
    )
    .await?;

    let block_hash = get_recent_block_hash(&client).await;
    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PRIVATE_CLOAD).unwrap().into();
    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let to = TxKind::Call(contract_addr);
    let output = EthApiOverrideClient::<Block>::call(
        &client,
        get_signed_seismic_tx_bytes(&wallet.inner, nonce, to, chain_id, read_calldata, block_hash)
            .await
            .into(),
        None,
        None,
        None,
    )
    .await
    .expect("CLOAD on private storage should succeed");

    let metadata =
        get_seismic_metadata(wallet.inner.address(), chain_id, nonce, to, U256::ZERO, block_hash);
    let decrypted = client_decrypt(metadata, &output).unwrap();
    assert_eq!(U256::from_be_slice(&decrypted), U256::from(42));
    Ok(())
}

/// Test that Solidity-level `readPublicSload()` succeeds.
/// (compiler uses regular SLOAD on public slot — should work)
#[tokio::test(flavor = "multi_thread")]
async fn test_solidity_read_public_sload_succeeds() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PUBLIC,
        U256::from(123),
    )
    .await?;

    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PUBLIC_SLOAD).unwrap().into();
    let result = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput { data: Some(read_calldata), ..Default::default() },
                ..Default::default()
            },
            seismic_elements: None,
        }
        .into(),
        None,
        None,
        None,
    )
    .await
    .expect("Solidity readPublicSload() should succeed");

    assert_eq!(
        U256::from_be_slice(&result),
        U256::from(123),
        "readPublicSload() should return 123"
    );
    Ok(())
}

/// Test that Solidity-level `readPrivateSload()` succeeds.
/// (compiler uses CLOAD internally for suint256 types, so this passes)
#[tokio::test(flavor = "multi_thread")]
async fn test_solidity_read_private_succeeds() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PRIVATE,
        U256::from(42),
    )
    .await?;

    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PRIVATE_SLOAD).unwrap().into();
    let result = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput { data: Some(read_calldata), ..Default::default() },
                ..Default::default()
            },
            seismic_elements: None,
        }
        .into(),
        None,
        None,
        None,
    )
    .await
    .expect("Solidity readPrivateSload() should succeed (compiler uses CLOAD)");

    assert_eq!(U256::from_be_slice(&result), U256::from(42), "readPrivateSload() should return 42");
    Ok(())
}

// FlaggedStorageTestContract bytecode and selectors
const FLAGGED_STORAGE_TEST_BYTECODE: &[u8] = &hex!("6080604052348015600e575f5ffd5b506103048061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610086575f3560e01c8063717d5de311610059578063717d5de3146100fe57806394193f111461011c5780639ad95ef81461013a578063ef5617921461015857610086565b806331845f7d1461008a578063420f38f8146100a65780634e0d898c146100c25780635d5b397f146100e0575b5f5ffd5b6100a4600480360381019061009f91906101f6565b610176565b005b6100c060048036038101906100bb9190610254565b61017f565b005b6100ca610189565b6040516100d7919061028e565b60405180910390f35b6100e8610192565b6040516100f5919061028e565b60405180910390f35b610106610197565b604051610113919061028e565b60405180910390f35b61012461019f565b604051610131919061028e565b60405180910390f35b6101426101aa565b60405161014f919061028e565b60405180910390f35b6101606101b6565b60405161016d919061028e565b60405180910390f35b805f8190555050565b8060018190b15050565b5f600154905090565b5f5481565b5f5f54905090565b5f5fb0805f5260205ff35b5f6001b0805f5260205ff35b5f6001b0905090565b5f5ffd5b5f819050919050565b6101d5816101c3565b81146101df575f5ffd5b50565b5f813590506101f0816101cc565b92915050565b5f6020828403121561020b5761020a6101bf565b5b5f610218848285016101e2565b91505092915050565b5f819050919050565b61023381610221565b811461023d575f5ffd5b50565b5f8135905061024e8161022a565b92915050565b5f60208284031215610269576102686101bf565b5b5f61027684828501610240565b91505092915050565b610288816101c3565b82525050565b5f6020820190506102a15f83018461027f565b9291505056fea2646970667358221220bed26217d42178260b773a5edf5b427f93dde38ce69f366f5ac8ace37b09e4fd64736f6c637829302e382e33312d646576656c6f702e323032352e31312e31322b636f6d6d69742e3637366264656363005a");
const FLAGGED_STORAGE_SET_PUBLIC: &str = "31845f7d"; // setPublic(uint256)
const FLAGGED_STORAGE_SET_PRIVATE: &str = "420f38f8"; // setPrivate(suint256)
const FLAGGED_STORAGE_READ_PUBLIC_SLOAD: &str = "717d5de3"; // readPublicSload()
const FLAGGED_STORAGE_READ_PRIVATE_SLOAD: &str = "ef561792"; // readPrivateSload()
const FLAGGED_STORAGE_READ_PRIVATE_SLOAD_RAW: &str = "4e0d898c"; // readPrivateSloadRaw()
const FLAGGED_STORAGE_READ_PRIVATE_CLOAD: &str = "9ad95ef8"; // readPrivateCload()
const FLAGGED_STORAGE_READ_PUBLIC_CLOAD: &str = "94193f11"; // readPublicCload()

const fn get_encryption_precompiles_contracts() -> Bytes {
    Bytes::from_static(&hex!("6080604052348015600e575f5ffd5b50335f5f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610dce8061005b5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806328696e361461004e5780638da5cb5b1461006a578063a061904014610088578063ce75255b146100a4575b5f5ffd5b61006860048036038101906100639190610687565b6100d4565b005b61007261019a565b60405161007f9190610711565b60405180910390f35b6100a2600480360381019061009d919061075d565b6101be565b005b6100be60048036038101906100b991906107c9565b610256565b6040516100cb9190610896565b60405180910390f35b5f6100dd610412565b90505f61012d8285858080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f820116905080830192505050505050506104f5565b9050816bffffffffffffffffffffffff167f093a34a48cc07b4bf1355d9c15ec71077c85342d872753188302f99341f961008260405160200161017091906108f0565b60405160208183030381529060405260405161018c9190610896565b60405180910390a250505050565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461024c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161024390610986565b60405180910390fd5b8060018190b15050565b60605f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146102e6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102dd90610986565b60405180910390fd5b5f838390501161032b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610322906109ee565b60405180910390fd5b5f606790505f6001b086868660405160200161034a9493929190610a92565b60405160208183030381529060405290505f5f8373ffffffffffffffffffffffffffffffffffffffff168360405161038291906108f0565b5f60405180830381855afa9150503d805f81146103ba576040519150601f19603f3d011682016040523d82523d5f602084013e6103bf565b606091505b509150915081610404576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103fb90610b3c565b60405180910390fd5b809450505050509392505050565b5f5f606490505f5f8273ffffffffffffffffffffffffffffffffffffffff1660206040516020016104439190610b9d565b60405160208183030381529060405260405161045f91906108f0565b5f60405180830381855afa9150503d805f8114610497576040519150601f19603f3d011682016040523d82523d5f602084013e61049c565b606091505b5091509150816104e1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104d890610c01565b60405180910390fd5b5f60208201519050805f1c94505050505090565b60605f606690505f6001b0858560405160200161051493929190610c1f565b60405160208183030381529060405290505f5f8373ffffffffffffffffffffffffffffffffffffffff168360405161054c91906108f0565b5f60405180830381855afa9150503d805f8114610584576040519150601f19603f3d011682016040523d82523d5f602084013e610589565b606091505b5091509150816105ce576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105c590610cc7565b60405180910390fd5b5f815111610611576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161060890610d55565b60405180910390fd5b8094505050505092915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261064757610646610626565b5b8235905067ffffffffffffffff8111156106645761066361062a565b5b6020830191508360018202830111156106805761067f61062e565b5b9250929050565b5f5f6020838503121561069d5761069c61061e565b5b5f83013567ffffffffffffffff8111156106ba576106b9610622565b5b6106c685828601610632565b92509250509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6106fb826106d2565b9050919050565b61070b816106f1565b82525050565b5f6020820190506107245f830184610702565b92915050565b5f819050919050565b61073c8161072a565b8114610746575f5ffd5b50565b5f8135905061075781610733565b92915050565b5f602082840312156107725761077161061e565b5b5f61077f84828501610749565b91505092915050565b5f6bffffffffffffffffffffffff82169050919050565b6107a881610788565b81146107b2575f5ffd5b50565b5f813590506107c38161079f565b92915050565b5f5f5f604084860312156107e0576107df61061e565b5b5f6107ed868287016107b5565b935050602084013567ffffffffffffffff81111561080e5761080d610622565b5b61081a86828701610632565b92509250509250925092565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f61086882610826565b6108728185610830565b9350610882818560208601610840565b61088b8161084e565b840191505092915050565b5f6020820190508181035f8301526108ae818461085e565b905092915050565b5f81905092915050565b5f6108ca82610826565b6108d481856108b6565b93506108e4818560208601610840565b80840191505092915050565b5f6108fb82846108c0565b915081905092915050565b5f82825260208201905092915050565b7f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f5f8201527f6e00000000000000000000000000000000000000000000000000000000000000602082015250565b5f610970602183610906565b915061097b82610916565b604082019050919050565b5f6020820190508181035f83015261099d81610964565b9050919050565b7f436970686572746578742063616e6e6f7420626520656d7074790000000000005f82015250565b5f6109d8601a83610906565b91506109e3826109a4565b602082019050919050565b5f6020820190508181035f830152610a05816109cc565b9050919050565b5f819050919050565b610a26610a218261072a565b610a0c565b82525050565b5f8160a01b9050919050565b5f610a4282610a2c565b9050919050565b610a5a610a5582610788565b610a38565b82525050565b828183375f83830152505050565b5f610a7983856108b6565b9350610a86838584610a60565b82840190509392505050565b5f610a9d8287610a15565b602082019150610aad8286610a49565b600c82019150610abe828486610a6e565b915081905095945050505050565b7f414553206465637279707420707265636f6d70696c652063616c6c206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610b26602283610906565b9150610b3182610acc565b604082019050919050565b5f6020820190508181035f830152610b5381610b1a565b9050919050565b5f63ffffffff82169050919050565b5f8160e01b9050919050565b5f610b7f82610b69565b9050919050565b610b97610b9282610b5a565b610b75565b82525050565b5f610ba88284610b86565b60048201915081905092915050565b7f524e4720507265636f6d70696c652063616c6c206661696c65640000000000005f82015250565b5f610beb601a83610906565b9150610bf682610bb7565b602082019050919050565b5f6020820190508181035f830152610c1881610bdf565b9050919050565b5f610c2a8286610a15565b602082019150610c3a8285610a49565b600c82019150610c4a82846108c0565b9150819050949350505050565b7f41455320656e637279707420707265636f6d70696c652063616c6c206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610cb1602283610906565b9150610cbc82610c57565b604082019050919050565b5f6020820190508181035f830152610cde81610ca5565b9050919050565b7f456e6372797074696f6e2063616c6c2072657475726e6564206e6f206f7574705f8201527f7574000000000000000000000000000000000000000000000000000000000000602082015250565b5f610d3f602283610906565b9150610d4a82610ce5565b604082019050919050565b5f6020820190508181035f830152610d6c81610d33565b905091905056fea2646970667358221220cdc3edd7891930a1ad58becbe2b3f7679ecfc78a3b1f8a803d4c381c8318287864736f6c637827302e382e32382d63692e323032342e31312e342b636f6d6d69742e32306261666332392e6d6f640058"))
}

fn get_input_data(selector: &str, value: B256) -> Bytes {
    let selector_bytes: Vec<u8> = hex::decode(&selector[0..8]).expect("Invalid selector");
    let value_bytes: Bytes = value.into();
    let mut input_data = Vec::new();
    input_data.extend_from_slice(&selector_bytes);
    input_data.extend_from_slice(&value_bytes);
    input_data.into()
}

fn concat_input_data(selector: &str, value: Bytes) -> Bytes {
    let selector_bytes: Vec<u8> = hex::decode(&selector[0..8]).expect("Invalid selector");
    let value_bytes: Bytes = value;
    let mut input_data = Vec::new();
    input_data.extend_from_slice(&selector_bytes);
    input_data.extend_from_slice(&value_bytes);
    input_data.into()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_rejects_code_override() -> eyre::Result<()> {
    let (_node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let victim_addr = Address::from_hex("0x0000000000000000000000000000000000001234").unwrap();

    let mut state_overrides = StateOverride::default();
    state_overrides.insert(
        victim_addr,
        AccountOverride {
            code: Some(Bytes::from_static(&hex!(
                "7f0000000000000000000000000000000000000000000000000000000000000001b060005260206000f3"
            ))),
            ..Default::default()
        },
    );

    let result = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(victim_addr)),
                gas: Some(1_000_000),
                chain_id: Some(chain_id),
                ..Default::default()
            },
            seismic_elements: None,
        }
        .into(),
        None,
        Some(state_overrides),
        None,
    )
    .await;

    match &result {
        Ok(output) => panic!(
            "eth_call with code override should be rejected, but got Ok: 0x{}",
            hex::encode(output)
        ),
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.to_lowercase().contains("code overrides are not permitted"),
                "Expected code override rejection error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_estimate_gas_rejects_code_override() -> eyre::Result<()> {
    let (_node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let victim_addr = Address::from_hex("0x0000000000000000000000000000000000001234").unwrap();

    let mut state_overrides = StateOverride::default();
    state_overrides.insert(
        victim_addr,
        AccountOverride {
            code: Some(Bytes::from_static(&hex!("6001b060005260206000f3"))),
            ..Default::default()
        },
    );

    let result = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        SeismicCallRequest::TransactionRequest(SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(victim_addr)),
                gas: Some(1_000_000),
                chain_id: Some(chain_id),
                ..Default::default()
            },
            seismic_elements: None,
        }),
        None,
        Some(state_overrides),
    )
    .await;

    match &result {
        Ok(gas) => {
            panic!("eth_estimateGas with code override should be rejected, but got Ok: {}", gas)
        }
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.to_lowercase().contains("code overrides are not permitted"),
                "Expected code override rejection error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_simulate_v1_rejects_code_override() -> eyre::Result<()> {
    let (_node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let victim_addr = Address::from_hex("0x0000000000000000000000000000000000001234").unwrap();

    let mut state_overrides = StateOverride::default();
    state_overrides.insert(
        victim_addr,
        AccountOverride {
            code: Some(Bytes::from_static(&hex!("6001b060005260206000f3"))),
            ..Default::default()
        },
    );

    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let tx_bytes = get_signed_deploy_tx_bytes(
        wallet.inner.clone(),
        nonce,
        chain_id,
        ContractTestContext::get_deploy_input_plaintext(),
    )
    .await;

    let block_with_code_override = SimBlock {
        block_overrides: None,
        state_overrides: Some(state_overrides),
        calls: vec![SeismicCallRequest::Bytes(tx_bytes)],
    };

    let simulate_payload = SimulatePayload::<SeismicCallRequest> {
        block_state_calls: vec![block_with_code_override],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };

    let result = EthApiOverrideClient::<Block>::simulate_v1(&client, simulate_payload, None).await;

    match &result {
        Ok(_) => panic!("eth_simulateV1 with code override should be rejected"),
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.to_lowercase().contains("code overrides are not permitted"),
                "Expected code override rejection error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

/// Anvil acct #6 — dev.json seeds 0 native + 1000 USDC at the predeploy's `_balances[addr]` slot.
fn usdc_only_signer() -> PrivateKeySigner {
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e".parse().unwrap()
}

/// `gas_price` is not part of the seismic-encrypted envelope, so mutating it post-encryption is
/// safe.
async fn get_signed_seismic_tx_bytes_with_gas_price(
    sk_wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    plaintext: Bytes,
    recent_block_hash: B256,
    gas_price: u128,
) -> Bytes {
    let mut tx = get_unsigned_seismic_tx_request(
        sk_wallet,
        nonce,
        to,
        chain_id,
        plaintext,
        recent_block_hash,
    )
    .await;
    tx.inner.gas_price = Some(gas_price);
    let signed = sign_tx(sk_wallet.clone(), tx).await;
    <SeismicTxEnvelope as Encodable2718>::encoded_2718(&signed).into()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_usdc_only_eth_call_signed_bytes() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let (contract_addr, recent_block_hash) =
        rpc_test_deploy_contract(&mut node, &client, chain_id, &wallet).await?;

    let signer = usdc_only_signer();
    let output = EthApiOverrideClient::<Block>::call(
        &client,
        get_signed_seismic_tx_bytes(
            &signer,
            get_nonce(&client, signer.address()).await,
            TxKind::Call(contract_addr),
            chain_id,
            ContractTestContext::get_is_odd_input_plaintext(),
            recent_block_hash,
        )
        .await
        .into(),
        None,
        None,
        None,
    )
    .await
    .expect("eth_call must honor USDC balance for caller_gas_allowance");

    assert!(!output.is_empty());
    Ok(())
}

/// simulateV1 does not route through `caller_gas_allowance`; seismic-revm's caller-deduct charges
/// in USDC at execution time instead. Locks in that routing.
#[tokio::test(flavor = "multi_thread")]
async fn test_usdc_only_eth_simulate_v1() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let (contract_addr, recent_block_hash) =
        rpc_test_deploy_contract(&mut node, &client, chain_id, &wallet).await?;

    let signer = usdc_only_signer();
    let tx_bytes = get_signed_seismic_tx_bytes(
        &signer,
        get_nonce(&client, signer.address()).await,
        TxKind::Call(contract_addr),
        chain_id,
        ContractTestContext::get_is_odd_input_plaintext(),
        recent_block_hash,
    )
    .await;

    let payload = SimulatePayload::<SeismicCallRequest> {
        block_state_calls: vec![SimBlock {
            block_overrides: None,
            state_overrides: None,
            calls: vec![SeismicCallRequest::Bytes(tx_bytes)],
        }],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };

    let result = EthApiOverrideClient::<Block>::simulate_v1(&client, payload, None)
        .await
        .expect("simulate_v1 must succeed for USDC-only wallet");
    assert!(!result.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_usdc_only_eth_estimate_gas_typed_data() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let (contract_addr, recent_block_hash) =
        rpc_test_deploy_contract(&mut node, &client, chain_id, &wallet).await?;

    let signer = usdc_only_signer();
    let typed = get_signed_seismic_tx_typed_data(
        &signer,
        get_nonce(&client, signer.address()).await,
        TxKind::Call(contract_addr),
        chain_id,
        ContractTestContext::get_is_odd_input_plaintext(),
        recent_block_hash,
    )
    .await;

    let gas = EthApiOverrideClient::<Block>::estimate_gas(&client, typed.into(), None, None)
        .await
        .expect("estimate_gas via typed-data must honor USDC balance");
    assert!(gas > U256::ZERO);
    Ok(())
}

/// 1000 USDC × 10^12 = 10^21 wei cap; `gas_price` = 10^18 → allowance 1000 gas, below 21000 floor.
#[tokio::test(flavor = "multi_thread")]
async fn test_usdc_only_insufficient_balance_high_gas_price() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let (contract_addr, recent_block_hash) =
        rpc_test_deploy_contract(&mut node, &client, chain_id, &wallet).await?;

    let signer = usdc_only_signer();
    let bytes = get_signed_seismic_tx_bytes_with_gas_price(
        &signer,
        get_nonce(&client, signer.address()).await,
        TxKind::Call(contract_addr),
        chain_id,
        ContractTestContext::get_is_odd_input_plaintext(),
        recent_block_hash,
        1_000_000_000_000_000_000u128,
    )
    .await;

    let result =
        EthApiOverrideClient::<Block>::estimate_gas(&client, bytes.into(), None, None).await;
    assert!(result.is_err(), "got {:?}", result);
    Ok(())
}

/// dev.json's USDC predeploy has no runtime bytecode, so the transfer is a no-op at the EVM
/// level — this asserts the estimateGas → sendRawTransaction → receipt flow, not balance movement.
#[tokio::test(flavor = "multi_thread")]
async fn test_usdc_only_susdc_transfer_e2e() -> eyre::Result<()> {
    let (mut node, client, chain_id, _wallet, _tasks) = setup_test_node().await?;

    let signer = usdc_only_signer();
    let recipient = Address::from_hex("0xaFD9e07a4955cB2E27a6DB7E2b55b05B4D928BD8").unwrap();
    let usdc = Address::from_hex("0x790701048922E265105fd6a4467a2901c2201C43").unwrap();

    // transfer(address,uint256) selector + 32-byte recipient + 1 SUSDC (6 dec raw).
    let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
    let mut recipient_word = [0u8; 32];
    recipient_word[12..].copy_from_slice(recipient.as_slice());
    calldata.extend_from_slice(&recipient_word);
    calldata.extend_from_slice(&U256::from(1_000_000u64).to_be_bytes::<32>());
    let plaintext = Bytes::from(calldata);

    // Seismic validator requires a recent block hash from the last 100 blocks.
    node.advance_block().await?;
    let recent = get_recent_block_hash(&client).await;
    let nonce = get_nonce(&client, signer.address()).await;

    let signed_bytes = get_signed_seismic_tx_bytes(
        &signer,
        nonce,
        TxKind::Call(usdc),
        chain_id,
        plaintext,
        recent,
    )
    .await;
    let estimate = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        signed_bytes.clone().into(),
        None,
        None,
    )
    .await
    .expect("eth_estimateGas must succeed for USDC-only wallet");
    assert!(estimate > U256::ZERO);

    let tx_hash = EthApiOverrideClient::<Block>::send_raw_transaction(&client, signed_bytes.into())
        .await
        .expect("eth_sendRawTransaction must succeed for USDC-only wallet");
    node.advance_block().await?;

    let receipt = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::transaction_receipt(&client, tx_hash)
    .await
    .unwrap()
    .unwrap();
    assert!(receipt.status());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_rejects_storage_override() -> eyre::Result<()> {
    let (_node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let victim_addr = Address::from_hex("0x0000000000000000000000000000000000001234").unwrap();

    let storage: alloy_primitives::map::B256HashMap<B256> =
        std::iter::once((B256::ZERO, B256::from(U256::from(1)))).collect();

    let mut state_overrides = StateOverride::default();
    state_overrides
        .insert(victim_addr, AccountOverride { state_diff: Some(storage), ..Default::default() });

    let result = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(victim_addr)),
                gas: Some(1_000_000),
                chain_id: Some(chain_id),
                ..Default::default()
            },
            seismic_elements: None,
        }
        .into(),
        None,
        Some(state_overrides),
        None,
    )
    .await;

    match &result {
        Ok(output) => panic!(
            "eth_call with storage override should be rejected, but got Ok: 0x{}",
            hex::encode(output)
        ),
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.to_lowercase().contains("storage overrides are not permitted"),
                "Expected storage override rejection error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_estimate_gas_rejects_storage_override() -> eyre::Result<()> {
    let (_node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let victim_addr = Address::from_hex("0x0000000000000000000000000000000000001234").unwrap();

    let storage: alloy_primitives::map::B256HashMap<B256> =
        std::iter::once((B256::ZERO, B256::from(U256::from(1)))).collect();

    let mut state_overrides = StateOverride::default();
    state_overrides
        .insert(victim_addr, AccountOverride { state_diff: Some(storage), ..Default::default() });

    let result = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        SeismicCallRequest::TransactionRequest(SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(victim_addr)),
                gas: Some(1_000_000),
                chain_id: Some(chain_id),
                ..Default::default()
            },
            seismic_elements: None,
        }),
        None,
        Some(state_overrides),
    )
    .await;

    match &result {
        Ok(gas) => {
            panic!("eth_estimateGas with storage override should be rejected, but got Ok: {}", gas)
        }
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.to_lowercase().contains("storage overrides are not permitted"),
                "Expected storage override rejection error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_simulate_v1_rejects_storage_override() -> eyre::Result<()> {
    let (_node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let victim_addr = Address::from_hex("0x0000000000000000000000000000000000001234").unwrap();

    let storage: alloy_primitives::map::B256HashMap<B256> =
        std::iter::once((B256::ZERO, B256::from(U256::from(1)))).collect();

    let mut state_overrides = StateOverride::default();
    state_overrides
        .insert(victim_addr, AccountOverride { state_diff: Some(storage), ..Default::default() });

    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let tx_bytes = get_signed_deploy_tx_bytes(
        wallet.inner.clone(),
        nonce,
        chain_id,
        ContractTestContext::get_deploy_input_plaintext(),
    )
    .await;

    let block_with_storage_override = SimBlock {
        block_overrides: None,
        state_overrides: Some(state_overrides),
        calls: vec![SeismicCallRequest::Bytes(tx_bytes)],
    };

    let simulate_payload = SimulatePayload::<SeismicCallRequest> {
        block_state_calls: vec![block_with_storage_override],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };

    let result = EthApiOverrideClient::<Block>::simulate_v1(&client, simulate_payload, None).await;

    match &result {
        Ok(_) => panic!("eth_simulateV1 with storage override should be rejected"),
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.to_lowercase().contains("storage overrides are not permitted"),
                "Expected storage override rejection error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

/// `eth_callMany` with an unsigned bundled call must apply the same `from`/fee/value/seismic
/// sanitization as `eth_call`. Mirrors `test_eth_call_rejects_sload_on_private_storage`: a raw
/// SLOAD on private storage must revert because the unsigned override clears `from`, leaving
/// the EVM with no caller authority for the private-storage access.
#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_many_rejects_unsigned_sload_on_private_storage() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PRIVATE,
        U256::from(42),
    )
    .await?;

    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PRIVATE_SLOAD_RAW).unwrap().into();
    let bundle =
        Bundle::from(vec![SeismicCallRequest::TransactionRequest(SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(wallet.inner.address()),
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput { data: Some(read_calldata), ..Default::default() },
                ..Default::default()
            },
            seismic_elements: None,
        })]);

    let mut results = EthApiOverrideClient::<Block>::call_many(&client, vec![bundle], None, None)
        .await
        .expect("callMany RPC call should return per-call results, not a top-level error");

    assert_eq!(results.len(), 1, "expected one bundle result");
    let mut bundle_results = results.remove(0);
    assert_eq!(bundle_results.len(), 1, "expected one call result");
    let call_result = bundle_results.remove(0);

    assert!(
        call_result.value.is_none(),
        "private SLOAD via callMany should not return a value, got {:?}",
        call_result.value
    );
    let err_msg = call_result
        .error
        .expect("private SLOAD via callMany should produce a per-call error")
        .to_lowercase();
    assert!(
        err_msg.contains("invalidprivatestorageaccess"),
        "expected 'InvalidPrivateStorageAccess' revert, got: {}",
        err_msg
    );
    Ok(())
}

/// `eth_callMany` with a signed Bytes request must run the full signed-read pipeline:
/// signature recovery, freshness validation, calldata decryption, execution, and response
/// encryption. Mirrors `test_eth_call_allows_cload_on_private_storage` but through the bundled
/// path.
#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_many_allows_signed_cload_on_private_storage() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PRIVATE,
        U256::from(42),
    )
    .await?;

    let block_hash = get_recent_block_hash(&client).await;
    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PRIVATE_CLOAD).unwrap().into();
    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let to = TxKind::Call(contract_addr);

    let signed_bytes =
        get_signed_seismic_tx_bytes(&wallet.inner, nonce, to, chain_id, read_calldata, block_hash)
            .await;

    let bundle = Bundle::from(vec![SeismicCallRequest::Bytes(signed_bytes)]);
    let mut results = EthApiOverrideClient::<Block>::call_many(&client, vec![bundle], None, None)
        .await
        .expect("CLOAD on private storage via callMany should succeed");

    assert_eq!(results.len(), 1, "expected one bundle result");
    let mut bundle_results = results.remove(0);
    assert_eq!(bundle_results.len(), 1, "expected one call result");
    let call_result = bundle_results.remove(0);
    let value = call_result.value.expect("call should have produced a value");

    let metadata =
        get_seismic_metadata(wallet.inner.address(), chain_id, nonce, to, U256::ZERO, block_hash);
    let decrypted = client_decrypt(metadata, &value).unwrap();
    assert_eq!(U256::from_be_slice(&decrypted), U256::from(42));
    Ok(())
}

/// Freshness validation (`recent_block_hash` lookback) must apply on the bundled signed-read
/// path too.`eth_callMany` shouldn't be a backdoor for replaying signed reads with stale
/// anchors.
#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call_many_rejects_signed_read_with_stale_recent_block_hash() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;

    let contract_addr = flagged_storage_deploy_and_write(
        &mut node,
        &client,
        chain_id,
        &wallet,
        FLAGGED_STORAGE_SET_PRIVATE,
        U256::from(42),
    )
    .await?;

    // Deliberately use a hash that cannot be on the canonical chain.
    let stale_block_hash = B256::ZERO;
    let read_calldata: Bytes = hex::decode(FLAGGED_STORAGE_READ_PRIVATE_CLOAD).unwrap().into();
    let nonce = get_nonce(&client, wallet.inner.address()).await;
    let signed_bytes = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Call(contract_addr),
        chain_id,
        read_calldata,
        stale_block_hash,
    )
    .await;

    let bundle = Bundle::from(vec![SeismicCallRequest::Bytes(signed_bytes)]);
    let result = EthApiOverrideClient::<Block>::call_many(&client, vec![bundle], None, None).await;

    match &result {
        Ok(output) => {
            panic!("callMany with stale recent_block_hash should be rejected, got Ok: {:?}", output)
        }
        Err(e) => {
            let err_msg = e.to_string().to_lowercase();
            assert!(
                err_msg.contains("recent_block_hash"),
                "expected RecentBlockHashNotFound error, got: {}",
                err_msg
            );
        }
    }
    Ok(())
}

/// Trace-serving namespaces (`debug_*`, `trace_*`, `ots_*`) must be unreachable on a Seismic
/// node even when the operator enables them: trace metadata (gas usage, revert paths,
/// call-tree shape, touched addresses) is a side channel on private state, even after the
/// payload sanitizers strip calldata/returndata/memory/stack.
///
/// The e2e harness launches nodes with `RpcModuleSelection::All`, so every namespace is
/// configured at the RPC layer — only the launch-time removal in
/// `SeismicAddOns::launch_add_ons` makes these methods unregistered.
#[tokio::test(flavor = "multi_thread")]
async fn test_trace_debug_ots_namespaces_disabled() -> eyre::Result<()> {
    let (_node, client, _chain_id, _wallet, _tasks) = setup_test_node().await?;

    let disabled_methods = [
        "debug_traceCall",
        "debug_traceTransaction",
        "debug_traceBlockByNumber",
        "trace_call",
        "trace_callMany",
        "trace_transaction",
        "trace_block",
        "ots_traceTransaction",
        "ots_getInternalOperations",
    ];

    for method in disabled_methods {
        let result = client.request::<serde_json::Value, _>(method, rpc_params![]).await;
        match result {
            Err(jsonrpsee::core::client::Error::Call(err)) => {
                assert_eq!(
                    err.code(),
                    jsonrpsee::types::error::ErrorCode::MethodNotFound.code(),
                    "{method} must be unregistered, got error: {err}"
                );
            }
            other => panic!("{method} must return method-not-found, got: {other:?}"),
        }
    }

    // Control: the standard eth namespace is still served.
    let block_number: String = client.request("eth_blockNumber", rpc_params![]).await?;
    assert!(block_number.starts_with("0x"), "unexpected eth_blockNumber response: {block_number}");

    Ok(())
}

/// `eth_createAccessList` is disabled on Seismic: the returned access list (touched addresses +
/// storage slots + call-tree shape) is a side channel on private state, and there is no signed-read
/// path to encrypt it. It is removed from the otherwise-served Eth namespace; see `node.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn test_create_access_list_disabled() -> eyre::Result<()> {
    let (_node, client, _chain_id, _wallet, _tasks) = setup_test_node().await?;

    let result =
        client.request::<serde_json::Value, _>("eth_createAccessList", rpc_params![]).await;
    match result {
        Err(jsonrpsee::core::client::Error::Call(err)) => {
            assert_eq!(
                err.code(),
                jsonrpsee::types::error::ErrorCode::MethodNotFound.code(),
                "eth_createAccessList must be unregistered, got error: {err}"
            );
        }
        other => panic!("eth_createAccessList must return method-not-found, got: {other:?}"),
    }

    // Control: a sibling Eth method we do not remove is still served.
    let block_number: String = client.request("eth_blockNumber", rpc_params![]).await?;
    assert!(block_number.starts_with("0x"), "unexpected eth_blockNumber response: {block_number}");

    Ok(())
}

/// Get the latest block number via `eth_blockNumber`.
async fn get_block_number(client: &jsonrpsee::http_client::HttpClient) -> u64 {
    let result: serde_json::Value =
        client.request("eth_blockNumber", rpc_params![]).await.expect("eth_blockNumber failed");
    let hex = result.as_str().expect("block number not a string");
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("failed to parse block number")
}

/// Build a signed Seismic tx fresh now but carrying a near-future `expires_at_block`, so it goes
/// stale after a couple of blocks. Calldata stays encrypted — freshness is checked before
/// decryption.
async fn get_expiring_seismic_tx_bytes(
    wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    recent_block_hash: B256,
    expires_at_block: u64,
) -> Bytes {
    let mut request = get_unsigned_seismic_tx_request(
        wallet,
        nonce,
        to,
        chain_id,
        get_plaintext(),
        recent_block_hash,
    )
    .await;
    request.seismic_elements.as_mut().expect("seismic request has elements").expires_at_block =
        expires_at_block;
    let signed = sign_tx(wallet.clone(), request).await;
    <SeismicTxEnvelope as Encodable2718>::encoded_2718(&signed).into()
}

/// Build a plain value-transfer tx, used to fill a nonce gap.
async fn get_plain_transfer_bytes(wallet: &PrivateKeySigner, nonce: u64, chain_id: u64) -> Bytes {
    let tx = TransactionRequest {
        from: None,
        to: Some(TxKind::Call(Address::random())),
        gas: Some(21000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(1e9 as u128),
        value: Some(U256::from(1)),
        nonce: Some(nonce),
        chain_id: Some(chain_id),
        ..Default::default()
    };
    let eth_wallet: EthereumWallet = wallet.clone().into();
    let envelope = tx.build(&eth_wallet).await.expect("failed to build transfer tx");
    TxEnvelope::encoded_2718(&envelope).into()
}

/// Returns whether `eth_getTransactionByHash` knows `hash` (pool or chain). Inspects the raw JSON
/// (null vs object) to avoid typed deserialization of queued seismic txs.
async fn tx_known(client: &jsonrpsee::http_client::HttpClient, hash: B256) -> bool {
    let result: serde_json::Value = client
        .request("eth_getTransactionByHash", rpc_params![hash])
        .await
        .expect("eth_getTransactionByHash failed");
    !result.is_null()
}

/// Regression test: a stale parked Seismic tx must be skipped by the payload builder, not abort
/// the build. Parks a nonce-gapped tx, lets it expire, fills the gap, then asserts the build still
/// produces a block (gap-filler mined, stale tx skipped).
#[tokio::test(flavor = "multi_thread")]
async fn test_stale_seismic_tx_is_skipped_not_fatal() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let signer = &wallet.inner;
    let address = signer.address();

    node.advance_block().await?;
    let recent_block_hash = get_recent_block_hash(&client).await;
    let head = get_block_number(&client).await;

    let expires_at_block = head + 2;
    let stale_tx = get_expiring_seismic_tx_bytes(
        signer,
        1,
        TxKind::Call(Address::random()),
        chain_id,
        recent_block_hash,
        expires_at_block,
    )
    .await;
    let stale_hash = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::send_raw_transaction(&client, stale_tx)
    .await
    .expect("nonce-gapped seismic tx should be accepted into the pool as queued");

    while get_block_number(&client).await <= expires_at_block {
        node.advance_block().await?;
    }

    // Fill the nonce gap (nonce 0), making the now-stale Seismic tx executable.
    let fill_tx = get_plain_transfer_bytes(signer, 0, chain_id).await;
    let fill_hash = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::send_raw_transaction(&client, fill_tx)
    .await
    .expect("gap-filler tx should be accepted");

    node.advance_block().await?;
    node.advance_block().await?;

    let fill_receipt = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::transaction_receipt(&client, fill_hash)
    .await
    .unwrap();
    assert!(fill_receipt.is_some(), "gap-filler tx should be mined; payload build must not abort");

    let stale_receipt = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::transaction_receipt(&client, stale_hash)
    .await
    .unwrap();
    assert!(stale_receipt.is_none(), "stale seismic tx must be skipped, not included in a block");

    assert_eq!(
        get_nonce(&client, address).await,
        1,
        "only the gap-filler (nonce 0) should be mined; the stale tx (nonce 1) was skipped"
    );

    Ok(())
}

/// Regression test: a parked Seismic tx that goes stale is evicted from the mempool. The nonce gap
/// is never filled — the tx stays queued, expires, and must be removed by the eviction task.
#[tokio::test(flavor = "multi_thread")]
async fn test_stale_seismic_tx_is_evicted_from_pool() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let signer = &wallet.inner;

    node.advance_block().await?;
    let recent_block_hash = get_recent_block_hash(&client).await;
    let head = get_block_number(&client).await;

    let expires_at_block = head + 2;
    let stale_tx = get_expiring_seismic_tx_bytes(
        signer,
        1,
        TxKind::Call(Address::random()),
        chain_id,
        recent_block_hash,
        expires_at_block,
    )
    .await;
    let stale_hash = EthApiClient::<
        SeismicTransactionRequest,
        SeismicTransactionSigned,
        SeismicBlock,
        SeismicTransactionReceipt,
        Header,
    >::send_raw_transaction(&client, stale_tx)
    .await
    .expect("nonce-gapped seismic tx should be accepted into the pool as queued");

    assert!(
        tx_known(&client, stale_hash).await,
        "parked seismic tx should be in the pool before expiry"
    );

    while get_block_number(&client).await <= expires_at_block {
        node.advance_block().await?;
    }

    // Eviction runs async on canonical-head notifications and is throttled, so advance several
    // heads and poll.
    let mut evicted = false;
    for _ in 0..20 {
        if !tx_known(&client, stale_hash).await {
            evicted = true;
            break;
        }
        node.advance_block().await?;
    }
    assert!(evicted, "stale parked seismic tx should be evicted from the mempool");

    Ok(())
}
