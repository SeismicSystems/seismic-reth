use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{NetworkWallet, ReceiptResponse, TransactionBuilder};
use alloy_primitives::{
    address,
    aliases::{B96, U96},
    bytes, hex,
    hex::FromHex,
    keccak256, Address, Bytes, IntoLogData, TxKind, B256, U256,
};
use alloy_provider::{PendingTransactionBuilder, Provider, SendableTx, WalletProvider};
use alloy_rpc_types::{Block, Header, TransactionInput, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolConstructor, SolType, SolValue};
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
use alloy_signer::Signer;
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::aliases::U192;

use crate::gas20_utils::{
    delegatee_account_bytecode, entrypoint_deployed_bytecode, gas_20_deployed_bytecode,
    paymaster_deployed_bytecode, seismic_provider_from_eth_wallet, BALANCE_OF_SELECTOR,
    DELEGATEE_EXECUTE_SELECTOR, DELEGATEE_GET_NONCE_SELECTOR, OWNERSHIP_TRANSFER_SELECTOR,
    TRANSFER_SELECTOR, ENTRYPOINT_GET_USER_OP_HASH_SELECTOR, ENTRYPOINT_GET_NONCE_SELECTOR,
};

// Define the user operation structure similar to the forge test
#[derive(Debug, Clone)]
struct PackedUserOperation {
    sender: Address,
    nonce: U256,
    init_code: Bytes,
    call_data: Bytes,
    account_gas_limits: B256,
    pre_verification_gas: U256,
    gas_fees: B256,
    paymaster_and_data: Bytes,
    signature: Bytes,
}

impl PackedUserOperation {
    fn abi_encode(&self) -> Bytes {
        let encoded = (
            self.sender,
            self.nonce,
            self.init_code.clone(),
            self.call_data.clone(),
            self.account_gas_limits,
            self.pre_verification_gas,
            self.gas_fees,
            self.paymaster_and_data.clone(),
            self.signature.clone(),
        ).abi_encode();
        Bytes::from(encoded)
    }
}

// Define the user operation event structure
#[derive(Debug, Clone)]
struct UserOperationEvent {
    user_op_hash: B256,
    sender: Address,
    paymaster: Address,
    nonce: U256,
    success: bool,
    actual_gas_cost: U256,
    actual_gas_used: U256,
}

#[tokio::test(flavor = "multi_thread")]
async fn gas20_test_conductor() {
    // set to true when I want to spin up my own node outside the test to see logs more easily
    let manual_debug = true;

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
    let base_wallet = Wallet::new(10).with_chain_id(chain_id);
    let deploy_provider = seismic_provider_from_eth_wallet(&base_wallet, &reth_rpc_url, 0);
    let alice_provider = seismic_provider_from_eth_wallet(&base_wallet, &reth_rpc_url, 1);
    let bob_provider = seismic_provider_from_eth_wallet(&base_wallet, &reth_rpc_url, 2);

    println!("deploy_provider addr: {:?}", deploy_provider.wallet().default_signer_address());
    println!("alice_provider addr: {:?}", alice_provider.wallet().default_signer_address());
    println!("bob_provider addr: {:?}", bob_provider.wallet().default_signer_address());

    let (
        gas20_contract_addr,
        entrypoint_contract_addr,
        paymaster_contract_addr,
        delegatee_contract_addr,
    ) = deploy_gas_contracts(&deploy_provider).await;

    // transfer ownership of gas20 to the paymaster
    let transfer_selector_bytes: Vec<u8> =
        hex::FromHex::from_hex(OWNERSHIP_TRANSFER_SELECTOR).unwrap();
    let transfer_data =
        [transfer_selector_bytes.as_slice(), &paymaster_contract_addr.abi_encode()].concat();
    let transfer_req = TransactionBuilder::<SeismicReth>::with_to(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            Bytes::from(transfer_data),
        ),
        gas20_contract_addr,
    );
    let transfer_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(transfer_req).await.unwrap();
    let transfer_tx_hash = transfer_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let transfer_receipt =
        deploy_provider.get_transaction_receipt(transfer_tx_hash.clone()).await.unwrap().unwrap();
    assert_eq!(transfer_receipt.status(), true, "failed to transfer ownership of gas20 to paymaster");

    // transfer some gas20 to alice
    // at the same time, include a delegation from alice to the delegatee contract
    let alice_address = alice_provider.wallet().default_signer_address();
    let amount = U256::from(100u64);
    let transfer_selector_bytes: Vec<u8> = hex::FromHex::from_hex(TRANSFER_SELECTOR).unwrap();
    let transfer_owner_data =
        [transfer_selector_bytes.as_slice(), &alice_address.abi_encode(), &amount.abi_encode()]
            .concat();
    let mut transfer_owner_tx = SeismicTransactionRequest::default();
    transfer_owner_tx = TransactionBuilder::<SeismicReth>::with_to(transfer_owner_tx, gas20_contract_addr);
    transfer_owner_tx = TransactionBuilder::<SeismicReth>::with_input(transfer_owner_tx, Bytes::from(transfer_owner_data));
    let signed_authorization = alice_7702_authorization(&alice_provider, entrypoint_contract_addr).await;
    transfer_owner_tx.authorization_list = Some(vec![signed_authorization.into()]);

    let transfer_owner_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(transfer_owner_tx).await.unwrap();
    let transfer_owner_tx_hash = transfer_owner_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let transfer_owner_receipt =
        deploy_provider.get_transaction_receipt(transfer_owner_tx_hash.clone()).await.unwrap().unwrap();
    assert_eq!(transfer_owner_receipt.status(), true, "failed to transfer gas20 from deployer to alice");

    // // check that the delegation was successful by getting the code of Alice's EOA
    let alice_eoa_code = deploy_provider.get_code_at(alice_address).await.unwrap();
    assert!(!alice_eoa_code.is_empty(), "Alice's EOA code should not be empty");
    println!("Alice's EOA code is non-empty!");
    let nonce = delegatee_get_nonce(&alice_provider).await;
    println!("Alice's nonce: {}", nonce);

    // Now test the Gas20 payment functionality similar to the forge test
    let seismic_treasury_addr = address!("0x5123000000000000000000000000000000000000");
    test_paymaster_with_gas20_payment(
        &deploy_provider,
        &alice_provider,
        &bob_provider,
        gas20_contract_addr,
        entrypoint_contract_addr,
        paymaster_contract_addr,
        delegatee_contract_addr,
        seismic_treasury_addr,
    )
    .await;
}

async fn deploy_gas_contracts(
    deploy_provider: &SeismicSignedProvider<SeismicReth>,
) -> (Address, Address, Address, Address) {
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
        deploy_provider.send_transaction(gas20_req).await.unwrap();
    let gas20_tx_hash = gas20_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let gas20_receipt =
        deploy_provider.get_transaction_receipt(gas20_tx_hash.clone()).await.unwrap().unwrap();
    let gas20_contract_addr = gas20_receipt.contract_address.unwrap();
    assert_eq!(gas20_receipt.status(), true);

    let gas20_code = deploy_provider.get_code_at(gas20_contract_addr).await.unwrap();
    assert!(!gas20_code.is_empty(), "Gas20 contract code should not be empty");

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
        deploy_provider.send_transaction(entrypoint_req).await.unwrap();
    let entrypoint_tx_hash = entrypoint_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let entrypoint_receipt =
        deploy_provider.get_transaction_receipt(entrypoint_tx_hash.clone()).await.unwrap().unwrap();
    let entrypoint_contract_addr = entrypoint_receipt.contract_address.unwrap();
    assert_eq!(entrypoint_receipt.status(), true);

    let entrypoint_code = deploy_provider.get_code_at(entrypoint_contract_addr).await.unwrap();
    assert!(!entrypoint_code.is_empty(), "Entrypoint contract code should not be empty");

    // Deploy Paymaster contract
    println!("Deploying Paymaster contract...");
    let seismic_treasury_addr = address!("0x5123000000000000000000000000000000000000");
    let paymaster_constructor_data: Vec<u8> = vec![
        entrypoint_contract_addr.abi_encode(),
        gas20_contract_addr.abi_encode(),
        seismic_treasury_addr.abi_encode(),
    ]
    .concat();
    let paymaster_input =
        [paymaster_deployed_bytecode().as_ref(), paymaster_constructor_data.as_ref()].concat();
    let paymaster_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            Bytes::from(paymaster_input),
        ),
        TxKind::Create,
    );
    let paymaster_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(paymaster_req).await.unwrap();
    let paymaster_tx_hash = paymaster_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let paymaster_receipt =
        deploy_provider.get_transaction_receipt(paymaster_tx_hash.clone()).await.unwrap().unwrap();
    let paymaster_contract_addr = paymaster_receipt.contract_address.unwrap();
    assert_eq!(paymaster_receipt.status(), true);

    let paymaster_code = deploy_provider.get_code_at(paymaster_contract_addr).await.unwrap();
    assert!(!paymaster_code.is_empty(), "Paymaster contract code should not be empty");

    // Deploy Delegatee Account contract
    println!("Deploying Delegatee Account contract...");

    // Combine the constructor data with the bytecode
    let delegatee_constructor_data = entrypoint_contract_addr.abi_encode();
    let delegatee_input =
        [delegatee_account_bytecode().as_ref(), delegatee_constructor_data.as_ref()].concat();

    let delegatee_req = TransactionBuilder::<SeismicReth>::with_kind(
        TransactionBuilder::<SeismicReth>::with_input(
            SeismicTransactionRequest::default(),
            Bytes::from(delegatee_input),
        ),
        TxKind::Create,
    );
    let delegatee_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(delegatee_req).await.unwrap();
    let delegatee_tx_hash = delegatee_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let delegatee_receipt =
        deploy_provider.get_transaction_receipt(delegatee_tx_hash.clone()).await.unwrap().unwrap();
    let delegatee_contract_addr = delegatee_receipt.contract_address.unwrap();
    assert_eq!(delegatee_receipt.status(), true);

    let delegatee_code = deploy_provider.get_code_at(delegatee_contract_addr).await.unwrap();
    assert!(!delegatee_code.is_empty(), "Delegatee Account contract code should not be empty");

    println!("All four contracts deployed successfully!");
    println!("Gas20: {:?}", gas20_contract_addr);
    println!("Entrypoint: {:?}", entrypoint_contract_addr);
    println!("Paymaster: {:?}", paymaster_contract_addr);
    println!("Delegatee Account: {:?}\n\n", delegatee_contract_addr);

    (
        gas20_contract_addr,
        entrypoint_contract_addr,
        paymaster_contract_addr,
        delegatee_contract_addr,
    )
}

async fn test_paymaster_with_gas20_payment(
    deploy_provider: &SeismicSignedProvider<SeismicReth>,
    alice_provider: &SeismicSignedProvider<SeismicReth>,
    bob_provider: &SeismicSignedProvider<SeismicReth>,
    gas20_contract_addr: Address,
    entrypoint_contract_addr: Address,
    paymaster_contract_addr: Address,
    delegatee_contract_addr: Address,
    treasury_addr: Address,
) {
    let alice_address = alice_provider.wallet().default_signer_address();
    let bob_address = bob_provider.wallet().default_signer_address();

    // 1. Check initial balances
    let alice_initial_balance =
        get_gas20_balance(deploy_provider, gas20_contract_addr, alice_address).await;
    let treasury_initial_balance =
        get_gas20_balance(deploy_provider, gas20_contract_addr, treasury_addr).await;

    println!("Alice initial Gas20 balance: {}", alice_initial_balance);
    println!("Treasury initial Gas20 balance: {}", treasury_initial_balance);
    // println!("Bob initial ETH balance: {}", bob_initial_balance);

    // 2. Construct calldata for Alice's account to execute
    // This would be a call to the delegatee account's execute function
    let execute_selector_bytes: Vec<u8> =
        hex::FromHex::from_hex(DELEGATEE_EXECUTE_SELECTOR).unwrap();
    let destination = Address::ZERO; // No destination for this test
    let value = U256::ZERO; // No ETH needed
    let function_call_data = Bytes::new(); // Empty function call data

    let call_data = [
        execute_selector_bytes.as_slice(),
        destination.abi_encode().as_slice(),
        value.abi_encode().as_slice(),
        function_call_data.abi_encode().as_slice(),
    ]
    .concat();

    // 3. Set gas parameters (similar to forge test)
    let gas_limit = U256::from(100000u64);
    let verification_gas_limit = U256::from(50000u64);
    let pre_verification_gas = U256::from(10000u64);
    let max_fee_per_gas = U256::from(20_000_000_000u64); // 20 gwei
    let max_priority_fee_per_gas = U256::from(2_000_000_000u64); // 2 gwei

    // 4. Pack gas parameters
    let account_gas_limits = pack_gas_limits(verification_gas_limit, gas_limit);
    let gas_fees = pack_gas_fees(max_priority_fee_per_gas, max_fee_per_gas);

    // 5. Calculate max cost for gas payment
    let max_cost = gas_limit * max_fee_per_gas;
    println!("Max cost: {}", max_cost);

    // 6. Pack paymaster data
    let paymaster_and_data =
        pack_paymaster_data(paymaster_contract_addr, verification_gas_limit, U256::from(50000u64));

    // 7. Get the current nonce first
    let current_nonce = delegatee_get_nonce(alice_provider).await;
    println!("Current nonce: {}", current_nonce);

    // 8. Generate user operation
    let user_op = PackedUserOperation {
        sender: alice_address,
        nonce: current_nonce,
        init_code: Bytes::new(),
        call_data: Bytes::from(call_data),
        account_gas_limits,
        pre_verification_gas,
        gas_fees,
        paymaster_and_data: Bytes::from(paymaster_and_data),
        signature: Bytes::new(),
    };

    // 9. Get user operation hash
    let user_op_hash = get_user_op_hash(deploy_provider, &user_op, entrypoint_contract_addr).await;

    // 10. Create signature (simplified for testing)
    let signature = alice_sign_hash(alice_provider, &user_op_hash).await;

    let mut user_op_with_signature = user_op.clone();
    user_op_with_signature.signature = signature.as_bytes().into();

    // // 11. Bob (bundler) submits the user operation
    // println!("Bob submitting user operation...");
    // let gas_before = bob_provider.get_balance(bob_address, None).await.unwrap();

    // let user_operations = vec![user_op_with_signature];
    // let result = handle_ops(bob_provider, entrypoint_contract_addr, user_operations, bob_address).await;

    // let gas_after = bob_provider.get_balance(bob_address, None).await.unwrap();
    // let bob_gas_used = gas_before - gas_after;

    // match result {
    //     Ok(_) => println!("User operation submitted successfully"),
    //     Err(e) => {
    //         println!("User operation failed: {:?}", e);
    //         return;
    //     }
    // }

    // 12. Check that the operation was successful by looking for UserOperationEvent
    // In a real implementation, you would parse the transaction receipt for events
    println!("Checking operation results...");

    // 13. Check Gas20 token balances after operation
    let alice_final_balance = get_gas20_balance(deploy_provider, gas20_contract_addr, alice_address).await;
    let treasury_final_balance =
        get_gas20_balance(deploy_provider, gas20_contract_addr, treasury_addr).await;

    println!("Alice final Gas20 balance: {}", alice_final_balance);
    println!("Treasury final Gas20 balance: {}", treasury_final_balance);

    // Alice should have paid some Gas20 tokens
    assert!(alice_final_balance < alice_initial_balance, "Alice should have paid Gas20 tokens");

    // Treasury should have received Gas20 tokens
    assert!(
        treasury_final_balance > treasury_initial_balance,
        "Treasury should have received Gas20 tokens"
    );

    // // 14. Check that Alice's EOA has no ETH (all gas paid through Gas20 tokens)
    // let alice_account_final_balance = alice_provider.get_balance(alice_address, None).await.unwrap();
    // assert_eq!(
    //     alice_account_final_balance,
    //     U256::ZERO,
    //     "Alice's EOA should have no ETH - all gas paid through Gas20 tokens"
    // );

    // // 15. Check that Bob is compensated for his actual gas costs
    // let bob_final_balance = bob_provider.get_balance(bob_address, None).await.unwrap();
    // let bob_compensation = bob_final_balance - bob_initial_balance;

    // // Bob should be compensated for his actual gas costs
    // assert_eq!(bob_compensation, bob_gas_used, "Bob should be refunded the gas cost");
    // println!("Bob compensation: {}", bob_compensation);

    // println!("Gas20 payment test completed successfully!");
}

async fn alice_7702_authorization(alice_provider: &SeismicSignedProvider<SeismicReth>, entrypoint_contract_addr: Address) -> SignedAuthorization {
    let alice_address = alice_provider.wallet().default_signer_address();
    println!("alice_7702_authorization alice_address: {:?}", alice_address);

    // This should be the nonce for the EOA's 7702 contract code (not the regular Ethereum nonce)
    // Our delegatee implementation uses the entrypoint contract's nonce for its own nonce
    // So we do a call to the entrypoint contract to get the nonce
    let nonce_selector_bytes: Vec<u8> =
        hex::FromHex::from_hex(ENTRYPOINT_GET_NONCE_SELECTOR).unwrap();
    let key = U192::ZERO;
    let nonce_data = [nonce_selector_bytes.as_slice(), &alice_address.abi_encode(), &key.abi_encode()].concat();
    let mut tx = SeismicTransactionRequest::default();
    tx = TransactionBuilder::<SeismicReth>::with_to(tx, entrypoint_contract_addr);
    tx = TransactionBuilder::<SeismicReth>::with_input(tx, Bytes::from(nonce_data));

    let output = alice_provider
        .seismic_call(SendableTx::Builder(tx))
        .await
        .unwrap();
    let nonce: u64 = U256::from_be_slice(&output).try_into().unwrap();

    let chain_id = U256::from(SeismicRethTestCommand::chain_id());

    let authorization = Authorization {
        chain_id,
        address: alice_address,
        nonce: nonce.into(),
    };
    let hash = authorization.signature_hash();
    let signature = alice_sign_hash(alice_provider, &hash).await;
    let signed_authorization = SignedAuthorization::new_unchecked(
        authorization,
        signature.v() as u8,
        signature.r(),
        signature.s(),
    );

    let recovered_address = signed_authorization.recover_authority().unwrap();
    println!("Recovered address: {:?}", recovered_address);
    assert_eq!(recovered_address, alice_address, "Recovered address should be the same as the signer");

    signed_authorization
}

// // Helper functions

async fn get_gas20_balance(
    provider: &SeismicSignedProvider<SeismicReth>,
    gas20_contract: Address,
    account: Address,
) -> U256 {
    let balance_of_selector_bytes: Vec<u8> = hex::FromHex::from_hex(BALANCE_OF_SELECTOR).unwrap();
    let deployer_balance_of_data =
        [balance_of_selector_bytes.as_slice(), &account.abi_encode()].concat();
    let output = provider
        .seismic_call(SendableTx::Builder(TransactionBuilder::<SeismicReth>::with_to(
            TransactionBuilder::<SeismicReth>::with_input(
                SeismicTransactionRequest::default(),
                Bytes::from(deployer_balance_of_data),
            ),
            gas20_contract,
        )))
        .await
        .unwrap();
    let balance = U256::from_be_slice(&output);
    balance
}

async fn delegatee_get_nonce(provider: &SeismicSignedProvider<SeismicReth>) -> U256 {
    let sender_addr = provider.wallet().default_signer_address();
    let nonce_selector_bytes: Vec<u8> =
        hex::FromHex::from_hex(DELEGATEE_GET_NONCE_SELECTOR).unwrap();
    let nonce_data = [nonce_selector_bytes.as_slice(), &sender_addr.abi_encode()].concat();

    // note: tx is to the sender, not the delegatee contract, 
    // because we are running the contract code from the sender address 7702-style
    // assumes the sender has already delegated to the delegatee contract
    let mut tx = SeismicTransactionRequest::default();
    tx = TransactionBuilder::<SeismicReth>::with_to(tx, sender_addr);
    tx = TransactionBuilder::<SeismicReth>::with_input(tx, Bytes::from(nonce_data));

    let output = provider
        .seismic_call(SendableTx::Builder(tx))
        .await
        .unwrap();
    let nonce = U256::from_be_slice(&output);
    nonce
}

fn pack_gas_limits(verification_gas_limit: U256, gas_limit: U256) -> B256 {
    let packed = (verification_gas_limit << 128) | gas_limit;
    B256::from(packed)
}

fn pack_gas_fees(max_priority_fee_per_gas: U256, max_fee_per_gas: U256) -> B256 {
    let packed = (max_priority_fee_per_gas << 128) | max_fee_per_gas;
    B256::from(packed)
}

fn pack_paymaster_data(
    paymaster: Address,
    verification_gas_limit: U256,
    post_op_gas_limit: U256,
) -> Vec<u8> {
    [paymaster.abi_encode(), verification_gas_limit.abi_encode(), post_op_gas_limit.abi_encode()]
        .concat()
}

async fn get_user_op_hash(provider: &SeismicSignedProvider<SeismicReth>, user_op: &PackedUserOperation, entrypoint: Address) -> B256 {
    let user_op_hash_selector_bytes: Vec<u8> =
        hex::FromHex::from_hex(ENTRYPOINT_GET_USER_OP_HASH_SELECTOR).unwrap();
    let user_op_hash_data = [user_op_hash_selector_bytes.as_slice(), &user_op.abi_encode()].concat();
    let output = provider
        .seismic_call(SendableTx::Builder(TransactionBuilder::<SeismicReth>::with_to(
            TransactionBuilder::<SeismicReth>::with_input(
                SeismicTransactionRequest::default(),
                Bytes::from(user_op_hash_data),
            ),
            entrypoint,
        )))
        .await
        .unwrap();
    let user_op_hash = B256::from_slice(&output);
    println!("User op hash: {:?}", user_op_hash);
    user_op_hash
}

fn format_user_op_hash_for_signing(user_op_hash: B256) -> B256 {
    // Format the hash for EIP-191 signing
    // Based on Solidity: mstore(0x00, "\x19Ethereum Signed Message:\n32") + mstore(0x1c, messageHash)
    let prefix = "\x19Ethereum Signed Message:\n32";
    let mut message = Vec::new();
    message.extend_from_slice(prefix.as_bytes()); // 28 bytes (0x1c)
    message.extend_from_slice(&user_op_hash.as_slice());   // 32 bytes (0x20)
    keccak256(&message)
}

async fn alice_sign_hash(_provider: &SeismicSignedProvider<SeismicReth>, hash: &B256) -> alloy_primitives::Signature {
    // provider.wallet().default_signer() only impls TxSigner, not Signer, so hardcoding alice here
    let base_wallet = Wallet::new(10).with_chain_id(SeismicRethTestCommand::chain_id());
    let signer_vec = Wallet::wallet_gen(&base_wallet);
    let alice_index = 1;
    let alice_signer = signer_vec[alice_index].clone();
    let signature = alice_signer.sign_hash(hash).await.unwrap();
    signature
}




// async fn handle_ops(
//     provider: &SeismicSignedProvider<SeismicReth>,
//     entrypoint: Address,
//     user_operations: Vec<PackedUserOperation>,
//     beneficiary: Address,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // This would call the handleOps function on the entrypoint contract
//     // For now, just simulate success
//     println!("Simulating handleOps call with {} user operations", user_operations.len());
//     Ok(())
// }
