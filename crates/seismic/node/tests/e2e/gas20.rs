use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_network::{NetworkWallet, ReceiptResponse, TransactionBuilder};
use alloy_primitives::{
    address, aliases::U192, bytes, hex, keccak256, Address, Bytes, TxKind, B256, U256,
};
use alloy_provider::{PendingTransactionBuilder, Provider, SendableTx, WalletProvider};
use alloy_signer::Signer;
use alloy_sol_types::{SolCall, SolConstructor, SolValue};
use reth_e2e_test_utils::wallet::Wallet;
use reth_seismic_node::utils::test_utils::SeismicRethTestCommand;
use seismic_alloy_network::SeismicReth;
use seismic_alloy_provider::{SeismicProviderExt, SeismicSignedProvider};
use seismic_alloy_rpc_types::SeismicTransactionRequest;
use std::{thread, time::Duration};
use tokio::sync::mpsc;

use crate::gas20_utils::{
    delegatee_account_bytecode, entrypoint_deployed_bytecode, gas_20_deployed_bytecode,
    paymaster_deployed_bytecode, seismic_provider_from_eth_wallet, IDelegateeAccount, IEntryPoint,
    IGas20, IPaymaster, BALANCE_OF_SELECTOR, ENTRYPOINT_GET_NONCE_SELECTOR,
    TRANSFER_SELECTOR,
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
    let transfer_data = IGas20::transferOwnershipCall { 0: paymaster_contract_addr }.abi_encode();
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
    assert_eq!(
        transfer_receipt.status(),
        true,
        "failed to transfer ownership of gas20 to paymaster"
    );

    // transfer some gas20 to alice
    // at the same time, include a delegation from alice to the delegatee contract
    let alice_address = alice_provider.wallet().default_signer_address();
    let amount = U256::from(10_000_000 * 10u128.pow(18));
    let transfer_selector_bytes: Vec<u8> = hex::FromHex::from_hex(TRANSFER_SELECTOR).unwrap();
    let transfer_owner_data =
        [transfer_selector_bytes.as_slice(), &alice_address.abi_encode(), &amount.abi_encode()]
            .concat();
    let mut transfer_owner_tx = SeismicTransactionRequest::default();
    transfer_owner_tx =
        TransactionBuilder::<SeismicReth>::with_to(transfer_owner_tx, gas20_contract_addr);
    transfer_owner_tx = TransactionBuilder::<SeismicReth>::with_input(
        transfer_owner_tx,
        Bytes::from(transfer_owner_data),
    );
    let signed_authorization = alice_7702_authorization(
        &alice_provider,
        entrypoint_contract_addr,
        delegatee_contract_addr,
    )
    .await;
    transfer_owner_tx.authorization_list = Some(vec![signed_authorization.into()]);

    let transfer_owner_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(transfer_owner_tx).await.unwrap();
    let transfer_owner_tx_hash = transfer_owner_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let transfer_owner_receipt = deploy_provider
        .get_transaction_receipt(transfer_owner_tx_hash.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        transfer_owner_receipt.status(),
        true,
        "failed to transfer gas20 from deployer to alice"
    );

    // // check that the delegation was successful by getting the code of Alice's EOA
    let alice_eoa_code = deploy_provider.get_code_at(alice_address).await.unwrap();
    assert!(!alice_eoa_code.is_empty(), "Alice's EOA code should not be empty");
    println!("Alice's EOA code is non-empty! About to try getting nonce...");
    println!("code: {:?}", alice_eoa_code);
    let nonce = delegatee_get_nonce(&alice_provider).await;
    println!("Alice's nonce: {}", nonce);

    // fund the paymaster with eth in the entrypoint
    let amount = U256::from(10_000_000_000_000_000_000_u64);
    let paymaster_deposit_data = IPaymaster::depositCall {}.abi_encode();
    let mut fund_paymaster_tx = SeismicTransactionRequest::default();
    fund_paymaster_tx =
        TransactionBuilder::<SeismicReth>::with_to(fund_paymaster_tx, paymaster_contract_addr);
    fund_paymaster_tx =
        TransactionBuilder::<SeismicReth>::with_input(fund_paymaster_tx, paymaster_deposit_data);
    fund_paymaster_tx = TransactionBuilder::<SeismicReth>::with_value(fund_paymaster_tx, amount);
    let fund_paymaster_pending_transaction: PendingTransactionBuilder<SeismicReth> =
        deploy_provider.send_transaction(fund_paymaster_tx).await.unwrap();
    let fund_paymaster_tx_hash = fund_paymaster_pending_transaction.tx_hash();
    thread::sleep(Duration::from_secs(1));
    let fund_paymaster_receipt = deploy_provider
        .get_transaction_receipt(fund_paymaster_tx_hash.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fund_paymaster_receipt.status(), true, "failed to fund paymaster");
    println!("paymaster funded successfully");

    // let check_paymaster_balance_data = IEntryPoint::getDepositInfoCall {
    //     0: paymaster_contract_addr,
    // }
    // .abi_encode();
    // let check_paymaster_balance_tx = SeismicTransactionRequest::default();
    // let check_paymaster_balance_req = TransactionBuilder::<SeismicReth>::with_to(
    //     check_paymaster_balance_tx,
    //     entrypoint_contract_addr,
    // );
    // let check_paymaster_balance_req = TransactionBuilder::<SeismicReth>::with_input(
    //     check_paymaster_balance_req,
    //     Bytes::from(check_paymaster_balance_data),
    // );
    // let balance =
    // deploy_provider.seismic_call(SendableTx::Builder(check_paymaster_balance_req)).await.
    // unwrap(); println!("balance: {:?}", balance);
    // let balance: U256 = B256::from_slice(&balance).into();
    // assert_eq!(balance, U256::from(10_000_000_000_000_000_000_u64));

    // Now test the Gas20 payment functionality similar to the forge test
    let seismic_treasury_addr = address!("0x5123000000000000000000000000000000000000");
    test_paymaster_with_gas20_payment(
        &deploy_provider,
        &alice_provider,
        &bob_provider,
        gas20_contract_addr,
        entrypoint_contract_addr,
        paymaster_contract_addr,
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
    let delegatee_constructor_data =
        IDelegateeAccount::constructorCall { _0: entrypoint_contract_addr }.abi_encode();
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
    let delegatee_entrypoint = IDelegateeAccount::entryPointCall {}.abi_encode();
    let delegatee_entrypoint_addr = deploy_provider
        .seismic_call(SendableTx::Builder(TransactionBuilder::<SeismicReth>::with_to(
            TransactionBuilder::<SeismicReth>::with_input(
                SeismicTransactionRequest::default(),
                Bytes::from(delegatee_entrypoint),
            ),
            delegatee_contract_addr,
        )))
        .await
        .unwrap();
    println!("real entrypoint: {:?}", entrypoint_contract_addr);
    println!("delegatee_entrypoint_addr: {:?}", delegatee_entrypoint_addr);

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
    let destination = Address::ZERO; // No destination for this test
    let value = U256::ZERO; // No ETH needed
    let function_call_data = Bytes::new(); // Empty function call data

    let call_data = IDelegateeAccount::executeCall {
        dest: destination,
        value,
        funcCallData: function_call_data,
    }
    .abi_encode();

    // 3. Set gas parameters (similar to forge test)
    let gas_limit = U256::from(100001u64);
    let verification_gas_limit = U256::from(50002u64);
    let pre_verification_gas = U256::from(10003u64);
    let max_fee_per_gas = U256::from(20_000_000_004u64); // 20 gwei
    let max_priority_fee_per_gas = U256::from(2_000_000_005u64); // 2 gwei

    // 4. Pack gas parameters
    let account_gas_limits = pack_gas_limits(verification_gas_limit, gas_limit);
    // let account_gas_limits = B256::from_slice(&account_gas_limits.as_slice());
    // let account_gas_limits =
    // B256::from_hex("0x0000000000000000000000000111c350000000000000000000000000000186a0").
    // unwrap();

    let gas_fees = pack_gas_fees(max_priority_fee_per_gas, max_fee_per_gas);

    println!("account_gas_limits: {:?}", account_gas_limits);
    println!("gas_fees: {:?}", gas_fees);

    // 5. Get paymaster balance
    // 5. Calculate max cost for gas payment
    let max_cost = gas_limit * max_fee_per_gas;
    println!("Max cost: {}", max_cost);

    // 6. Pack paymaster data
    let paymaster_and_data = Bytes::from(pack_paymaster_data(
        paymaster_contract_addr,
        verification_gas_limit,
        U256::from(50000u64),
    ));
    println!("paymaster_and_data: {:?}", paymaster_and_data);
    let paymaster_and_data = vec![
        paymaster_contract_addr.abi_encode_packed(),
        bytes!("0000000000000000000000000000c3520000000000000000000000000000c350")
            .abi_encode_packed(),
    ]
    .concat();

    // 7. Get the current nonce first
    let current_nonce = delegatee_get_nonce(alice_provider).await;
    println!("Current nonce: {}", current_nonce);

    // 8. Generate user operation
    let user_op = PackedUserOperation {
        sender: alice_address,
        nonce: current_nonce,
        init_code: Bytes::new(),
        call_data: Bytes::from(call_data),
        account_gas_limits: account_gas_limits.into(),
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

    // 11. Bob (bundler) submits the user operation
    println!("Bob submitting user operation...");
    let alice_balance_before = alice_provider.get_balance(alice_address).await.unwrap();
    let gas_before = bob_provider.get_balance(bob_address).await.unwrap();

    let user_operations = vec![user_op_with_signature];
    handle_ops(bob_provider, entrypoint_contract_addr, user_operations, bob_address).await;

    let gas_after = bob_provider.get_balance(bob_address).await.unwrap();
    let bob_gas_used = gas_before - gas_after;

    // 12. Check that the operation was successful by looking for UserOperationEvent
    // In a real implementation, you would parse the transaction receipt for events
    println!("Checking operation results...");

    // 13. Check Gas20 token balances after operation
    thread::sleep(Duration::from_secs(1));
    let alice_final_balance =
        get_gas20_balance(deploy_provider, gas20_contract_addr, alice_address).await;
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
    println!("treasury received a fee");

    // 14. Check that Alice's EOA has no ETH (all gas paid through Gas20 tokens)
    let alice_account_final_balance = alice_provider.get_balance(alice_address).await.unwrap();
    assert_eq!(
        alice_account_final_balance, alice_balance_before,
        "Alice's EOA should not have spent any ETH"
    );

    // 15. Check that Bob is compensated for his actual gas costs
    assert_eq!(bob_gas_used, U256::ZERO, "Bob should be compensated for his actual gas costs");

    println!("Gas20 payment test completed successfully!");
}

async fn alice_7702_authorization(
    alice_provider: &SeismicSignedProvider<SeismicReth>,
    entrypoint_contract_addr: Address,
    delegatee_contract_addr: Address,
) -> SignedAuthorization {
    let alice_address = alice_provider.wallet().default_signer_address();
    println!("alice_7702_authorization alice_address: {:?}", alice_address);

    // This should be the nonce for the EOA's 7702 contract code (not the regular Ethereum nonce)
    // Our delegatee implementation uses the entrypoint contract's nonce for its own nonce
    // So we do a call to the entrypoint contract to get the nonce
    let nonce_selector_bytes: Vec<u8> =
        hex::FromHex::from_hex(ENTRYPOINT_GET_NONCE_SELECTOR).unwrap();
    let key = U192::ZERO;
    let nonce_data =
        [nonce_selector_bytes.as_slice(), &alice_address.abi_encode(), &key.abi_encode()].concat();
    let mut tx = SeismicTransactionRequest::default();
    tx = TransactionBuilder::<SeismicReth>::with_to(tx, entrypoint_contract_addr);
    tx = TransactionBuilder::<SeismicReth>::with_input(tx, Bytes::from(nonce_data));

    let output = alice_provider.seismic_call(SendableTx::Builder(tx)).await.unwrap();
    let nonce: u64 = U256::from_be_slice(&output).try_into().unwrap();

    let chain_id = U256::from(SeismicRethTestCommand::chain_id());

    let authorization =
        Authorization { chain_id, address: delegatee_contract_addr, nonce: nonce.into() };
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
    assert_eq!(
        recovered_address, alice_address,
        "Recovered address should be the same as the signer"
    );

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
    println!("delegatee_get_nonce sender_addr: {:?}", sender_addr);
    let nonce_data = IDelegateeAccount::getNonceCall {}.abi_encode();

    // note: tx is to the sender, not the delegatee contract,
    // because we are running the contract code from the sender address 7702-style
    // assumes the sender has already delegated to the delegatee contract
    let mut tx = SeismicTransactionRequest::default();
    tx = TransactionBuilder::<SeismicReth>::with_to(tx, sender_addr);
    tx = TransactionBuilder::<SeismicReth>::with_input(tx, Bytes::from(nonce_data));

    let output = provider.seismic_call(SendableTx::Builder(tx)).await.unwrap();
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
    (paymaster, verification_gas_limit, post_op_gas_limit).abi_encode_packed()
}

async fn get_user_op_hash(
    provider: &SeismicSignedProvider<SeismicReth>,
    user_op: &PackedUserOperation,
    entrypoint: Address,
) -> B256 {
    // Get UserOpHashHash based on what the entrypoint expects
    let user_op_tuple = (
        user_op.sender,
        user_op.nonce,
        user_op.init_code.clone(),
        user_op.call_data.clone(),
        user_op.account_gas_limits,
        user_op.pre_verification_gas,
        user_op.gas_fees,
        user_op.paymaster_and_data.clone(),
        user_op.signature.clone(),
    );
    let user_op_hash_data = IEntryPoint::getUserOpHashCall { 0: user_op_tuple }.abi_encode();

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
    let user_op_hash_raw = B256::from_slice(&output);
    println!("entrypoint userOpHash: {:?}", user_op_hash_raw);

    // Formate the UserOpHashHash with the EthSignedMessage format
    let prefix = b"\x19Ethereum Signed Message:\n32";
    let mut eth_message = Vec::with_capacity(prefix.len() + 32);
    eth_message.extend_from_slice(prefix);
    eth_message.extend_from_slice(user_op_hash_raw.as_slice());
    let formatted_user_op_hash = keccak256(&eth_message);
    println!("formattedUserOpHash: {:?}", formatted_user_op_hash);
    formatted_user_op_hash
}

async fn alice_sign_hash(
    _provider: &SeismicSignedProvider<SeismicReth>,
    hash: &B256,
) -> alloy_primitives::Signature {
    // provider.wallet().default_signer() only impls TxSigner, not Signer, so hardcoding alice here
    let base_wallet = Wallet::new(10).with_chain_id(SeismicRethTestCommand::chain_id());
    let signer_vec = Wallet::wallet_gen(&base_wallet);
    let alice_index = 1;
    let alice_signer = signer_vec[alice_index].clone();
    let signature = alice_signer.sign_hash(hash).await.unwrap();
    signature
}

async fn handle_ops(
    provider: &SeismicSignedProvider<SeismicReth>,
    entrypoint: Address,
    user_operations: Vec<PackedUserOperation>,
    beneficiary: Address,
) {
    println!("in handle_ops. entrypoint: {:?}, user_operations: {:?}", entrypoint, user_operations);
    let user_op = user_operations[0].clone(); // we know there is only one op for this test

    // Convert PackedUserOperation to tuple format for the interface
    let user_op_tuple = (
        user_op.sender,
        user_op.nonce,
        user_op.init_code,
        user_op.call_data,
        user_op.account_gas_limits,
        user_op.pre_verification_gas,
        user_op.gas_fees,
        user_op.paymaster_and_data,
        user_op.signature,
    );

    println!("user_op encoded: {:?}", Bytes::from(user_op_tuple.abi_encode()));

    // Use the generated interface to create the call data
    let call_data =
        IEntryPoint::handleOpsCall { ops: vec![user_op_tuple], beneficiary }.abi_encode();

    let pending_tx = provider
        .send_transaction(TransactionBuilder::<SeismicReth>::with_to(
            TransactionBuilder::<SeismicReth>::with_input(
                SeismicTransactionRequest::default(),
                Bytes::from(call_data),
            ),
            entrypoint,
        ))
        .await
        .unwrap();
    let tx_hash = pending_tx.tx_hash();
    thread::sleep(Duration::from_secs(1));

    let receipt = provider.get_transaction_receipt(tx_hash.clone()).await.unwrap().unwrap();
    assert!(receipt.status(), "handle_ops should succeed");
}
