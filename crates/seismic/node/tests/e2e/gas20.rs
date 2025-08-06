use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{NetworkWallet, ReceiptResponse, TransactionBuilder};
use alloy_primitives::{
    address,
    aliases::{B96, U96},
    hex,
    hex::FromHex,
    keccak256, Address, Bytes, IntoLogData, TxKind, B256, U256,
};
use alloy_provider::{PendingTransactionBuilder, Provider, SendableTx};
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
use alloy_provider::WalletProvider;

use crate::gas20_utils::{
    delegatee_account_bytecode, entrypoint_deployed_bytecode, gas_20_deployed_bytecode,
    paymaster_deployed_bytecode, seismic_provider_from_eth_wallet,
};
use crate::gas20_utils::TRANSFER_SELECTOR;

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

    let (
        gas20_contract_addr,
        entrypoint_contract_addr,
        paymaster_contract_addr,
        delegatee_contract_addr,
    ) = deploy_gas_contracts(&deploy_provider).await;

    // transfer some gas20 to alice
    let alice_address = alice_provider.wallet().default_signer_address();
    let amount = U256::from(1000000000000000000u64);
    let transfer_data = [TRANSFER_SELECTOR.as_bytes(), &alice_address.abi_encode(), &amount.abi_encode()].concat();
    let transfer_req = TransactionBuilder::<SeismicReth>::with_input(
        SeismicTransactionRequest::default(),
        Bytes::from(transfer_data),
    );
    let transfer_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(transfer_req).await.unwrap();
    let transfer_tx_hash = transfer_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    println!("Transfer tx_hash: {:?}", transfer_tx_hash);

    let transfer_receipt =
        deploy_provider.get_transaction_receipt(transfer_tx_hash.clone()).await.unwrap().unwrap();
    assert_eq!(transfer_receipt.status(), true, "failed to transfer gas20 from deployer to alice");
    

    // Now test the Gas20 payment functionality similar to the forge test
    let seismic_treasury_addr = address!("0x5123000000000000000000000000000000000000");
    // test_paymaster_with_gas20_payment(
    //     &deploy_provider,
    //     &alice_provider,
    //     &bob_provider,
    //     gas20_contract_addr,
    //     entrypoint_contract_addr,
    //     paymaster_contract_addr,
    //     delegatee_contract_addr,
    //     seismic_treasury_addr,
    // )
    // .await;
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
    println!("Gas20 contract deployment tx_hash: {:?}", gas20_tx_hash);

    let gas20_receipt =
        deploy_provider.get_transaction_receipt(gas20_tx_hash.clone()).await.unwrap().unwrap();
    let gas20_contract_addr = gas20_receipt.contract_address.unwrap();
    println!("Gas20 contract deployed at: {:?}", gas20_contract_addr);
    assert_eq!(gas20_receipt.status(), true);

    let gas20_code = deploy_provider.get_code_at(gas20_contract_addr).await.unwrap();
    assert!(!gas20_code.is_empty(), "Gas20 contract code should not be empty");
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
        deploy_provider.send_transaction(entrypoint_req).await.unwrap();
    let entrypoint_tx_hash = entrypoint_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    println!("Entrypoint contract deployment tx_hash: {:?}", entrypoint_tx_hash);

    let entrypoint_receipt =
        deploy_provider.get_transaction_receipt(entrypoint_tx_hash.clone()).await.unwrap().unwrap();
    let entrypoint_contract_addr = entrypoint_receipt.contract_address.unwrap();
    println!("Entrypoint contract deployed at: {:?}", entrypoint_contract_addr);
    assert_eq!(entrypoint_receipt.status(), true);

    let entrypoint_code = deploy_provider.get_code_at(entrypoint_contract_addr).await.unwrap();
    assert!(!entrypoint_code.is_empty(), "Entrypoint contract code should not be empty");
    println!("Entrypoint contract code verified");

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
    println!("Paymaster contract deployment tx_hash: {:?}", paymaster_tx_hash);

    let paymaster_receipt =
        deploy_provider.get_transaction_receipt(paymaster_tx_hash.clone()).await.unwrap().unwrap();
    let paymaster_contract_addr = paymaster_receipt.contract_address.unwrap();
    println!("Paymaster contract deployed at: {:?}", paymaster_contract_addr);
    assert_eq!(paymaster_receipt.status(), true);

    let paymaster_code = deploy_provider.get_code_at(paymaster_contract_addr).await.unwrap();
    assert!(!paymaster_code.is_empty(), "Paymaster contract code should not be empty");
    println!("Paymaster contract code verified");

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
    println!("Delegatee Account contract deployment tx_hash: {:?}", delegatee_tx_hash);

    let delegatee_receipt =
        deploy_provider.get_transaction_receipt(delegatee_tx_hash.clone()).await.unwrap().unwrap();
    let delegatee_contract_addr = delegatee_receipt.contract_address.unwrap();
    println!("Delegatee Account contract deployed at: {:?}", delegatee_contract_addr);
    assert_eq!(delegatee_receipt.status(), true);

    let delegatee_code = deploy_provider.get_code_at(delegatee_contract_addr).await.unwrap();
    assert!(!delegatee_code.is_empty(), "Delegatee Account contract code should not be empty");
    println!("Delegatee Account contract code verified");

    println!("All four contracts deployed successfully!");
    println!("Gas20: {:?}", gas20_contract_addr);
    println!("Entrypoint: {:?}", entrypoint_contract_addr);
    println!("Paymaster: {:?}", paymaster_contract_addr);
    println!("Delegatee Account: {:?}", delegatee_contract_addr);

    (
        gas20_contract_addr,
        entrypoint_contract_addr,
        paymaster_contract_addr,
        delegatee_contract_addr,
    )
}

// async fn test_paymaster_with_gas20_payment(
//     deploy_provider: &SeismicSignedProvider<SeismicReth>,
//     alice_provider: &SeismicSignedProvider<SeismicReth>,
//     bob_provider: &SeismicSignedProvider<SeismicReth>,
//     gas20_contract_addr: Address,
//     entrypoint_contract_addr: Address,
//     paymaster_contract_addr: Address,
//     delegatee_contract_addr: Address,
//     treasury_addr: Address,
// ) {

//     // 1.

//     // 1. Check initial balances
//     let alice_initial_balance =
//         get_gas20_balance(provider, gas20_contract_addr, alice_address).await;
//     let treasury_initial_balance =
//         get_gas20_balance(provider, gas20_contract_addr, treasury_addr).await;
//     let bob_initial_balance = provider.get_balance(bob_address, None).await.unwrap();

//     println!("Alice initial Gas20 balance: {}", alice_initial_balance);
//     println!("Treasury initial Gas20 balance: {}", treasury_initial_balance);
//     println!("Bob initial ETH balance: {}", bob_initial_balance);

//     // 2. Construct calldata for Alice's account to execute
//     // This would be a call to the delegatee account's execute function
//     let execute_selector = keccak256("execute(address,uint256,bytes)".as_bytes())[0..4].to_vec();
//     let destination = Address::ZERO; // No destination for this test
//     let value = U256::ZERO; // No ETH needed
//     let function_call_data = Bytes::new(); // Empty function call data

//     let call_data = [
//         execute_selector,
//         destination.abi_encode(),
//         value.abi_encode(),
//         function_call_data.abi_encode(),
//     ]
//     .concat();

//     // 3. Set gas parameters (similar to forge test)
//     let gas_limit = U256::from(100000u64);
//     let verification_gas_limit = U256::from(50000u64);
//     let pre_verification_gas = U256::from(10000u64);
//     let max_fee_per_gas = U256::from(20_000_000_000u64); // 20 gwei
//     let max_priority_fee_per_gas = U256::from(2_000_000_000u64); // 2 gwei

//     // 4. Pack gas parameters
//     let account_gas_limits = pack_gas_limits(verification_gas_limit, gas_limit);
//     let gas_fees = pack_gas_fees(max_priority_fee_per_gas, max_fee_per_gas);

//     // 5. Calculate max cost for gas payment
//     let max_cost = gas_limit * max_fee_per_gas;
//     println!("Max cost: {}", max_cost);

//     // 6. Pack paymaster data
//     let paymaster_and_data =
//         pack_paymaster_data(paymaster_contract_addr, verification_gas_limit,
// U256::from(50000u64));

//     // 7. Get the current nonce first
//     let current_nonce = get_account_nonce(provider, delegatee_contract_addr).await;
//     println!("Current nonce: {}", current_nonce);

//     // 8. Generate user operation
//     let user_op = PackedUserOperation {
//         sender: delegatee_contract_addr,
//         nonce: current_nonce,
//         init_code: Bytes::new(),
//         call_data: Bytes::from(call_data),
//         account_gas_limits,
//         pre_verification_gas,
//         gas_fees,
//         paymaster_and_data: Bytes::from(paymaster_and_data),
//         signature: Bytes::new(),
//     };

//     // 9. Get user operation hash
//     let user_op_hash = get_user_op_hash(&user_op, entrypoint_contract_addr);

//     // 10. Create signature (simplified for testing)
//     let signature = Bytes::new(); // Mock signature for testing

//     let mut user_op_with_signature = user_op.clone();
//     user_op_with_signature.signature = signature;

//     // 11. Bob (bundler) submits the user operation
//     println!("Bob submitting user operation...");
//     let gas_before = provider.get_balance(bob_address, None).await.unwrap();

//     let user_operations = vec![user_op_with_signature];
//     let result = handle_ops(provider, entrypoint_contract_addr, user_operations,
// bob_address).await;

//     let gas_after = provider.get_balance(bob_address, None).await.unwrap();
//     let bob_gas_used = gas_before - gas_after;

//     match result {
//         Ok(_) => println!("User operation submitted successfully"),
//         Err(e) => {
//             println!("User operation failed: {:?}", e);
//             return;
//         }
//     }

//     // 12. Check that the operation was successful by looking for UserOperationEvent
//     // In a real implementation, you would parse the transaction receipt for events
//     println!("Checking operation results...");

//     // 13. Check Gas20 token balances after operation
//     let alice_final_balance = get_gas20_balance(provider, gas20_contract_addr,
// alice_address).await;     let treasury_final_balance =
//         get_gas20_balance(provider, gas20_contract_addr, treasury_addr).await;

//     println!("Alice final Gas20 balance: {}", alice_final_balance);
//     println!("Treasury final Gas20 balance: {}", treasury_final_balance);

//     // Alice should have paid some Gas20 tokens
//     assert!(alice_final_balance < alice_initial_balance, "Alice should have paid Gas20 tokens");

//     // Treasury should have received Gas20 tokens
//     assert!(
//         treasury_final_balance > treasury_initial_balance,
//         "Treasury should have received Gas20 tokens"
//     );

//     // 14. Check that Alice's EOA has no ETH (all gas paid through Gas20 tokens)
//     let alice_account_final_balance = provider.get_balance(alice_address, None).await.unwrap();
//     assert_eq!(
//         alice_account_final_balance,
//         U256::ZERO,
//         "Alice's EOA should have no ETH - all gas paid through Gas20 tokens"
//     );

//     // 15. Check that Bob is compensated for his actual gas costs
//     let bob_final_balance = provider.get_balance(bob_address, None).await.unwrap();
//     let bob_compensation = bob_final_balance - bob_initial_balance;

//     // Bob should be compensated for his actual gas costs
//     assert_eq!(bob_compensation, bob_gas_used, "Bob should be refunded the gas cost");
//     println!("Bob compensation: {}", bob_compensation);

//     println!("Gas20 payment test completed successfully!");
// }

// // Helper functions

// async fn get_gas20_balance(
//     provider: &SeismicSignedProvider<SeismicReth>,
//     gas20_contract: Address,
//     account: Address,
// ) -> U256 {
//     // This would call the balanceOf function on the Gas20 contract
//     // For now, return a mock value
//     U256::from(1000000u64)
// }

// async fn get_account_nonce(
//     provider: &SeismicSignedProvider<SeismicReth>,
//     account: Address,
// ) -> U256 {
//     // This would call the getNonce function on the account contract
//     // For now, return a mock value
//     U256::from(0u64)
// }

// fn pack_gas_limits(verification_gas_limit: U256, gas_limit: U256) -> B256 {
//     let packed = (verification_gas_limit << 128) | gas_limit;
//     B256::from(packed)
// }

// fn pack_gas_fees(max_priority_fee_per_gas: U256, max_fee_per_gas: U256) -> B256 {
//     let packed = (max_priority_fee_per_gas << 128) | max_fee_per_gas;
//     B256::from(packed)
// }

// fn pack_paymaster_data(
//     paymaster: Address,
//     verification_gas_limit: U256,
//     post_op_gas_limit: U256,
// ) -> Vec<u8> {
//     [paymaster.abi_encode(), verification_gas_limit.abi_encode(), post_op_gas_limit.abi_encode()]
//         .concat()
// }

// fn get_user_op_hash(user_op: &PackedUserOperation, entrypoint: Address) -> B256 {
//     // This would call the getUserOpHash function on the entrypoint contract
//     // For now, return a mock hash
//     keccak256(format!("{:?}{:?}{:?}", user_op.sender, user_op.nonce, entrypoint).as_bytes())
// }

// fn format_user_op_hash_for_signing(user_op_hash: B256) -> B256 {
//     // Format the hash for EIP-191 signing
//     let prefix = "\x19Ethereum Signed Message:\n32";
//     let message = [keccak256(prefix.as_bytes()), user_op_hash.0].concat();
//     keccak256(&message)
// }

// fn sign_user_op_hash(hash: &B256, _wallet: &()) -> Bytes {
//     // Mock signature for testing
//     Bytes::new()
// }

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
