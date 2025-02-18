//! This file is used to test the features of the seismic node without rpc interactions.
//! See integration.rs for rpc interactions.
use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{bytes::Buf, hex, Address, Bytes, TxKind, U256};
use eyre::Ok;
use reth_chainspec::DEV;
use reth_e2e_test_utils::setup_engine;
use reth_enclave::{ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT};
use reth_tracing::tracing::*;
use seismic_node::{
    node::SeismicNode,
    utils::{
        seismic_payload_attributes,
        start_mock_enclave_server,
        test_utils::{client_decrypt, get_signed_seismic_tx_bytes, IntegrationTestContext},
    },
};
use std::str::FromStr;

// should we re-write tests/it-tx.json with new values?
// NOTE: only set this to true if we have changed our protocol
const REWRITE_IT_TX: bool = false;

#[tokio::test(flavor = "multi_thread")]
async fn contract() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let chain_id = DEV.chain;

    debug!(target: "e2e:contract", ?DEV, "dev chain");

    let (mut nodes, _tasks, wallet) =
        setup_engine::<SeismicNode>(2, DEV.clone(), false, seismic_payload_attributes).await?;
    start_mock_enclave_server(ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT).await;
    debug!(target: "e2e:contract", "setup seismic node");
    let mut second_node = nodes.pop().unwrap();
    let mut first_node = nodes.pop().unwrap();
    let mut nonce = 0;
    let mut block_number;

    let acc = first_node
        .rpc
        .get_account(Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")?, 0)
        .await?;
    debug!(target: "e2e:contract", ?acc, "account");

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
    let input = Bytes::from_static(&hex!("60806040525f5f8190b150610285806100175f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806324a7f0b71461004357806343bd0d701461005f578063d09de08a1461007d575b5f5ffd5b61005d600480360381019061005891906100f6565b610087565b005b610067610090565b604051610074919061013b565b60405180910390f35b6100856100a7565b005b805f8190b15050565b5f600160025fb06100a19190610181565b14905090565b5f5f81b0809291906100b8906101de565b919050b150565b5f5ffd5b5f819050919050565b6100d5816100c3565b81146100df575f5ffd5b50565b5f813590506100f0816100cc565b92915050565b5f6020828403121561010b5761010a6100bf565b5b5f610118848285016100e2565b91505092915050565b5f8115159050919050565b61013581610121565b82525050565b5f60208201905061014e5f83018461012c565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61018b826100c3565b9150610196836100c3565b9250826101a6576101a5610154565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101e8826100c3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361021a576102196101b1565b5b60018201905091905056fea2646970667358221220ea421d58b6748a9089335034d76eb2f01bceafe3dfac2e57d9d2e766852904df64736f6c63782c302e382e32382d646576656c6f702e323032342e31322e392b636f6d6d69742e39383863313261662e6d6f64005d"));
    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Create,
        chain_id.id(),
        input.clone(),
    )
    .await;

    let mut itx: IntegrationTestContext = IntegrationTestContext::new(&raw_tx);

    // decoding the transaction to verify the payload
    let mut input_bytes = vec![0u8; raw_tx.len()];
    raw_tx.clone().copy_to_slice(&mut input_bytes);
    let mut input_bytes_slice = &input_bytes[..];
    let decoded_tx = <TxEnvelope as Decodable2718>::decode_2718(&mut input_bytes_slice)
        .expect("decoding failed");

    debug!(
        target: "e2e:contract",
        ?decoded_tx ,
        "decoded transaction",
    );

    debug!(
        target: "e2e:contract",
        ?raw_tx,
        "transaction deploy contract",
    );

    // Make the nodes advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;
    itx.tx_hash(&tx_hash);
    let (payload, _) = first_node.advance_block().await?;
    let block_hash = payload.block().hash();
    block_number = payload.block().number;
    first_node.assert_new_block(tx_hash, block_hash, block_number).await?;
    second_node.engine_api.update_forkchoice(block_hash, block_hash).await?;
    second_node.assert_new_block(tx_hash, block_hash, block_number).await?;

    let tx_receipt = second_node.rpc.transaction_receipt(tx_hash).await?.unwrap();
    let contract_addr = tx_receipt.contract_address.unwrap();
    itx.contract(&contract_addr);

    let code = second_node.rpc.get_code(contract_addr, block_number).await?;
    itx.code(&code);

    debug!(
        target: "e2e:contract",
        ?contract_addr,
        ?code,
        "contract deployed",
    );

    // call contract function to verify
    nonce += 1;

    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Call(contract_addr),
        chain_id.id(),
        Bytes::from_static(&hex!("43bd0d70")),
    )
    .await;
    itx.signed_call(&raw_tx);

    let encrypted_output: Bytes = first_node.rpc.signed_call(raw_tx.clone(), block_number).await?;
    itx.encrypted_output(&encrypted_output);
    let decrypted_output = client_decrypt(&wallet.inner, nonce, &encrypted_output).await;
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::ZERO);

    debug!(
        target: "e2e:contract",
        ?raw_tx,
        ?encrypted_output,
        ?decrypted_output,
        "transaction call isOdd() before change",
    );

    // ==================== second block for changing the state of the contract account
    let input = Bytes::from_static(&hex!(
        "24a7f0b70000000000000000000000000000000000000000000000000000000000000003"
    ));
    let raw_tx = get_signed_seismic_tx_bytes(
        &wallet.inner,
        nonce,
        TxKind::Call(contract_addr),
        chain_id.id(),
        input.clone(),
    )
    .await;
    itx.raw_tx(&raw_tx);
    debug!(
        target: "e2e:contract",
        ?raw_tx,
        "transaction to change contract storage",
    );

    // Make the first node advance
    let tx_hash = first_node.rpc.inject_tx(raw_tx).await?;
    itx.tx_hash(&tx_hash);
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
        Bytes::from_static(&hex!("43bd0d70")),
    )
    .await;
    itx.signed_call(&raw_tx);

    let encrypted_output: Bytes = first_node.rpc.signed_call(raw_tx.clone(), block_number).await?;
    itx.encrypted_output(&encrypted_output);
    let decrypted_output: Bytes = client_decrypt(&wallet.inner, nonce, &encrypted_output).await;
    debug!(
        target: "e2e:contract",
        ?raw_tx,
        ?encrypted_output,
        ?decrypted_output,
        "transaction call isOdd() after change",
    );
    assert_eq!(U256::from_be_slice(&decrypted_output), U256::from(1));

    if REWRITE_IT_TX && IntegrationTestContext::should_rewrite_it() {
        itx.write();
    }

    Ok(())
}
