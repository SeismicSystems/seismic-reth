use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{ReceiptResponse, TransactionBuilder};
use alloy_primitives::{
    aliases::{B96, U96},
    hex,
    hex::FromHex,
    Bytes, IntoLogData, TxKind, B256, U256,
};
use alloy_provider::{PendingTransactionBuilder, Provider, SendableTx};
use alloy_rpc_types::{Block, Header, TransactionInput, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolValue};
use reth_e2e_test_utils::wallet::Wallet;
use reth_rpc_eth_api::EthApiClient;
use reth_seismic_node::utils::test_utils::{
    client_decrypt, get_nonce, get_signed_seismic_tx_bytes, get_signed_seismic_tx_typed_data,
    get_unsigned_seismic_tx_request, SeismicRethTestCommand,
};
use reth_seismic_primitives::{SeismicBlock, SeismicTransactionSigned};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use seismic_alloy_network::{wallet::SeismicWallet, SeismicReth};
use seismic_alloy_provider::{
    test_utils::ContractTestContext, SeismicProviderExt, SeismicSignedProvider,
};
use seismic_alloy_rpc_types::{
    SeismicCallRequest, SeismicTransactionReceipt, SeismicTransactionRequest, SimBlock,
    SimulatePayload,
};
use seismic_enclave::aes_decrypt;
use std::{thread, time::Duration};
use tokio::sync::mpsc;

use crate::gas20_utils::{gas_20_deployed_bytecode, entrypoint_deployed_bytecode, paymaster_deployed_bytecode, delegatee_account_bytecode};

#[tokio::test(flavor = "multi_thread")]
async fn gas20_test_conductor() {
    // set to true when I want to spin up my own node outside the test to see logs more easily
    let manual_debug = false;

    let mut shutdown_tx_top: Option<mpsc::Sender<()>> = None;
    if !manual_debug {
        // spin up a reth node
        let (tx, mut rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        shutdown_tx_top = Some(shutdown_tx);

        SeismicRethTestCommand::run(tx, shutdown_rx).await;
        rx.recv().await.unwrap();
    }

    test_gas20().await;

    if !manual_debug {
        let _ = shutdown_tx_top.unwrap().try_send(()).unwrap();
        println!("shutdown signal sent");
        thread::sleep(Duration::from_secs(1));
    }
}

async fn test_gas20() {
    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet: SeismicWallet<SeismicReth> = SeismicWallet::from(_wallet.inner);

    let provider = SeismicSignedProvider::new(wallet, reqwest::Url::parse(&reth_rpc_url).unwrap());

    // Deploy Gas20 contract
    println!("Deploying Gas20 contract...");
    let gas20_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            gas_20_deployed_bytecode(),
        ),
        TxKind::Create,
    );
    let gas20_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        provider.send_transaction(gas20_req).await.unwrap();
    let gas20_tx_hash = gas20_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    println!("Gas20 contract deployment tx_hash: {:?}", gas20_tx_hash);

    let gas20_receipt = provider.get_transaction_receipt(gas20_tx_hash.clone()).await.unwrap().unwrap();
    let gas20_contract_addr = gas20_receipt.contract_address.unwrap();
    println!("Gas20 contract deployed at: {:?}", gas20_contract_addr);
    assert_eq!(gas20_receipt.status(), true);

    let gas20_code = provider.get_code_at(gas20_contract_addr).await.unwrap();
    assert_eq!(gas_20_deployed_bytecode(), gas20_code);
    println!("Gas20 contract code verified");

    // Deploy Entrypoint contract
    println!("Deploying Entrypoint contract...");
    let entrypoint_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            entrypoint_deployed_bytecode(),
        ),
        TxKind::Create,
    );
    let entrypoint_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        provider.send_transaction(entrypoint_req).await.unwrap();
    let entrypoint_tx_hash = entrypoint_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    println!("Entrypoint contract deployment tx_hash: {:?}", entrypoint_tx_hash);

    let entrypoint_receipt = provider.get_transaction_receipt(entrypoint_tx_hash.clone()).await.unwrap().unwrap();
    let entrypoint_contract_addr = entrypoint_receipt.contract_address.unwrap();
    println!("Entrypoint contract deployed at: {:?}", entrypoint_contract_addr);
    assert_eq!(entrypoint_receipt.status(), true);

    let entrypoint_code = provider.get_code_at(entrypoint_contract_addr).await.unwrap();
    assert_eq!(entrypoint_deployed_bytecode(), entrypoint_code);
    println!("Entrypoint contract code verified");

    // Deploy Paymaster contract
    println!("Deploying Paymaster contract...");
    let paymaster_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            paymaster_deployed_bytecode(),
        ),
        TxKind::Create,
    );
    let paymaster_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        provider.send_transaction(paymaster_req).await.unwrap();
    let paymaster_tx_hash = paymaster_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    println!("Paymaster contract deployment tx_hash: {:?}", paymaster_tx_hash);

    let paymaster_receipt = provider.get_transaction_receipt(paymaster_tx_hash.clone()).await.unwrap().unwrap();
    let paymaster_contract_addr = paymaster_receipt.contract_address.unwrap();
    println!("Paymaster contract deployed at: {:?}", paymaster_contract_addr);
    assert_eq!(paymaster_receipt.status(), true);

    let paymaster_code = provider.get_code_at(paymaster_contract_addr).await.unwrap();
    assert_eq!(paymaster_deployed_bytecode(), paymaster_code);
    println!("Paymaster contract code verified");

    // Deploy Delegatee Account contract
    println!("Deploying Delegatee Account contract...");
    let delegatee_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            delegatee_account_bytecode(),
        ),
        TxKind::Create,
    );
    let delegatee_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        provider.send_transaction(delegatee_req).await.unwrap();
    let delegatee_tx_hash = delegatee_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    println!("Delegatee Account contract deployment tx_hash: {:?}", delegatee_tx_hash);

    let delegatee_receipt = provider.get_transaction_receipt(delegatee_tx_hash.clone()).await.unwrap().unwrap();
    let delegatee_contract_addr = delegatee_receipt.contract_address.unwrap();
    println!("Delegatee Account contract deployed at: {:?}", delegatee_contract_addr);
    assert_eq!(delegatee_receipt.status(), true);

    let delegatee_code = provider.get_code_at(delegatee_contract_addr).await.unwrap();
    assert_eq!(delegatee_account_bytecode(), delegatee_code);
    println!("Delegatee Account contract code verified");

    println!("All four contracts deployed successfully!");
    println!("Gas20: {:?}", gas20_contract_addr);
    println!("Entrypoint: {:?}", entrypoint_contract_addr);
    println!("Paymaster: {:?}", paymaster_contract_addr);
    println!("Delegatee Account: {:?}", delegatee_contract_addr);
}
