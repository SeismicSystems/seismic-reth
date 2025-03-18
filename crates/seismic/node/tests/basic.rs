//! This file is used to test the features of the seismic node without rpc interactions.
//! See integration.rs for rpc interactions.
use alloy_primitives::{Bytes, TxKind, U256};
use alloy_provider::layers::seismic::test_utils;
use reth_chainspec::SEISMIC_DEV;
use reth_e2e_test_utils::setup_engine;
use reth_enclave::start_default_mock_enclave_server;
use reth_tracing::tracing::*;
use seismic_node::{
    node::SeismicNode,
    utils::{
        seismic_payload_attributes,
        test_utils::{get_signed_seismic_tx_bytes, UnitTestContext},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn contract() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let chain_id = SEISMIC_DEV.chain;

    let (mut nodes, _tasks, wallet) =
        setup_engine::<SeismicNode>(2, SEISMIC_DEV.clone(), false, seismic_payload_attributes)
            .await?;
    start_default_mock_enclave_server().await;
    debug!(target: "e2e:contract", "setup seismic node");
    let mut second_node = nodes.pop().unwrap();
    let mut first_node = nodes.pop().unwrap();
    let mut nonce = 0;
    let mut block_number;

    // ==================== first block for encrypted transaction ====================
    // Contract deployed
    //     pragma solidity ^0.8.13;
    // contract SeismicCounter {
    //     suint256 number;
    //     constructor() payable {
    //         number = 0;
    //     }
    //     function setNumber(suint256 newNumber) public {
    //         number = newNumber;
    //     }
    //     function increment() public {
    //         number++;
    //     }
    //     function isOdd() public view returns (bool) {
    //         return number % 2 == 1;
    //     }
    // }
    // deploy contract
    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Create,
        chain_id.id(),
        test_utils::ContractTestContext::get_deploy_input_plaintext(),
    )
    .await;

    // Make the nodes advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;
    let (payload, _) = first_node.advance_block().await?;
    let block_hash = payload.block().hash();
    block_number = payload.block().number;
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;
    second_node.assert_new_block(tx_hash, block_hash, block_number).await?;

    let tx_receipt = second_node.rpc.transaction_receipt(tx_hash).await?.unwrap();
    println!("tx_receipt: {:?}", tx_receipt);
    assert_eq!(tx_receipt.status(), true);
    let contract_addr = tx_receipt.contract_address.unwrap();

    let code = second_node.rpc.get_code(contract_addr, block_number).await?;
    assert_eq!(test_utils::ContractTestContext::get_code(), code);

    // call contract function to verify
    nonce += 1;

    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Call(contract_addr),
        chain_id.id(),
        test_utils::ContractTestContext::get_is_odd_input_plaintext(),
    )
    .await;

    let encrypted_output: Bytes = first_node.rpc.signed_call(raw_tx.clone(), block_number).await?;
    let decrypted_output = UnitTestContext::client_decrypt(&encrypted_output);
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::ZERO);

    debug!(
        target: "e2e:contract",
        ?raw_tx,
        ?encrypted_output,
        ?decrypted_output,
        "transaction call isOdd() before change",
    );

    // ==================== second block for changing the state of the contract account
    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Call(contract_addr),
        chain_id.id(),
        test_utils::ContractTestContext::get_set_number_input_plaintext(),
    )
    .await;

    // Make the first node advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;
    let (payload, _) = first_node.advance_block().await?;
    let block_hash = payload.block().hash();
    block_number = payload.block().number;
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;
    second_node.assert_new_block(tx_hash, block_hash, 2).await?;

    // call contract function to verify
    nonce += 1;
    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Call(contract_addr),
        chain_id.id(),
        test_utils::ContractTestContext::get_is_odd_input_plaintext(),
    )
    .await;

    let encrypted_output: Bytes = first_node.rpc.signed_call(raw_tx.clone(), block_number).await?;
    let decrypted_output = UnitTestContext::client_decrypt(&encrypted_output);
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::from(1));

    Ok(())
}
