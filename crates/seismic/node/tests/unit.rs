//! The motivation of this file is to include unit tests for seismic features that are currently
// scattered across the codebase
use alloy_consensus::{SignableTransaction, TxSeismic};
use alloy_primitives::{hex, Address, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};
use core::str::FromStr;
use enr::EnrKey;
use reth_enclave::EnclaveError;
use reth_evm::ConfigureEvmEnv;
use reth_primitives::TransactionSigned;
use reth_revm::primitives::{EVMError, TxEnv};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use seismic_node::utils::test_utils::UnitTestContext;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seismic_transactions() {
    let unit_test_context = UnitTestContext::new().await;
    test_fill_tx_env(&unit_test_context);
    test_fill_tx_env_decryption_error(&unit_test_context);
    test_encoding_decoding_signed_seismic_tx();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seismic_client_encoding_decoding_test() {
    let tx_seismic = TxSeismic {
        chain_id: 31337,
        nonce: 2,
        gas_price: 1000000000,
        gas_limit: 100000,
        to: alloy_primitives::TxKind::Call(
            Address::from_str("0xd3e8763675e4c425df46cc3b5c0f6cbdac396046").unwrap()
        ),
        value: alloy_primitives::U256::from(1000000000000000u64),
        input: alloy_primitives::Bytes::from(
            hex::decode("fc3c2cf4943c327f19af0efaf3b07201f608dd5c8e3954399a919b72588d3872b6819ac3d13d3656cbb38833a39ffd1e73963196a1ddfa9e4a5d595fdbebb875").unwrap()
        ),
        seismic_elements: alloy_consensus::transaction::TxSeismicElements {
            encryption_pubkey: seismic_enclave::PublicKey::from_slice(
                &hex::decode("028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0").unwrap()
            ).unwrap(),
            encryption_nonce: alloy_primitives::aliases::U96::from_str("0xbe038ada26fea4ebcb4a6107").unwrap(),
            message_version: 0,
        },
    };

    let tx_seismic_clone = tx_seismic.clone();

    // Encode and print each field of tx_seismic
    let mut out = Vec::new();
    Encodable::encode(&tx_seismic.chain_id, &mut out);
    println!(
        "chain_id: bytes: {:?} rlp: {:?}",
        Bytes::from(tx_seismic.chain_id.to_be_bytes()),
        Bytes::from(out.clone())
    );

    out.clear();
    Encodable::encode(&tx_seismic.nonce, &mut out);
    println!(
        "nonce: bytes: {:?} rlp: {:?}",
        Bytes::from(tx_seismic.nonce.to_be_bytes()),
        Bytes::from(out.clone())
    );

    out.clear();
    Encodable::encode(&tx_seismic.gas_price, &mut out);
    println!(
        "gas_price: bytes: {:?} rlp: {:?}",
        Bytes::from(tx_seismic.gas_price.to_be_bytes()),
        Bytes::from(out.clone())
    );

    out.clear();
    Encodable::encode(&tx_seismic.gas_limit, &mut out);
    println!(
        "gas_limit: bytes: {:?} rlp: {:?}",
        Bytes::from(tx_seismic.gas_limit.to_be_bytes()),
        Bytes::from(out.clone())
    );

    out.clear();
    Encodable::encode(&tx_seismic.to, &mut out);
    println!("to: bytes: {:?} rlp: {:?}", (tx_seismic.to), Bytes::from(out.clone()));

    out.clear();
    Encodable::encode(&tx_seismic.value, &mut out);
    println!(
        "value: bytes: {:?} rlp: {:?}",
        Bytes::from(U256::to_be_bytes::<32>(&tx_seismic.value)),
        Bytes::from(out.clone())
    );

    out.clear();
    Encodable::encode(&tx_seismic.input, &mut out);
    println!(
        "input: bytes: {:?} rlp: {:?}",
        Bytes::from(tx_seismic.input),
        Bytes::from(out.clone())
    );

    out.clear();
    Encodable::encode(&tx_seismic.seismic_elements, &mut out);
    println!("seismic_elements: rlp: {:?}", Bytes::from(out.clone()));

    let mut out = Vec::new();
    tx_seismic_clone.encode_for_signing(&mut out);
    println!("encoding: bytes: {:?} rlp: {:?}", Bytes::from(out.clone()), Bytes::from(out));

    let signature = UnitTestContext::sign_seismic_tx(&tx_seismic_clone);
    let signed_tx = tx_seismic_clone.into_signed(signature);
    let mut out = Vec::new();
    signed_tx.eip2718_encode(&mut out);
    println!("signed encoding: {:0x}", Bytes::from(out));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seismic_tx_encoding_decoding() {
    let encoding = hex::decode("4af89c827a6902843b9aca00830186a094d3e8763675e4c425df46cc3b5c0f6cbdac39604687038d7ea4c68000a1028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a08cbe038ada26fea4ebcb4a610780b840fc3c2cf4943c327f19af0efaf3b07201f608dd5c8e3954399a919b72588d3872b6819ac3d13d3656cbb38833a39ffd1e73963196a1ddfa9e4a5d595fdbebb875").unwrap();
    let tx_seismic =
        recover_raw_transaction::<TransactionSigned>(&encoding).unwrap().as_signed().clone();
    println!("tx_seismic: {:?}", tx_seismic);
}

// This route is used to test the encoding and decoding of the signed seismic tx
fn test_encoding_decoding_signed_seismic_tx() {
    let encoding = UnitTestContext::get_signed_seismic_tx_encoding();
    let decoded_signed_tx =
        recover_raw_transaction::<TransactionSigned>(&encoding).unwrap().as_signed().clone();
    assert_eq!(decoded_signed_tx, UnitTestContext::get_signed_seismic_tx());
}

fn test_fill_tx_env(unit_test_context: &UnitTestContext) {
    let tx_signed = UnitTestContext::get_signed_seismic_tx();
    let mut tx_env = TxEnv::default();
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let _ = unit_test_context.evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender).unwrap();
    assert!(UnitTestContext::get_plaintext() == tx_env.data)
}

// Decryption error is expected when the encryption public key in transaction is invalid
fn test_fill_tx_env_decryption_error(unit_test_context: &UnitTestContext) {
    let mut tx_seismic = UnitTestContext::get_seismic_tx();
    tx_seismic.seismic_elements.encryption_pubkey =
        UnitTestContext::get_wrong_private_key().public();

    let signature = UnitTestContext::sign_seismic_tx(&tx_seismic);
    let tx_signed: TransactionSigned =
        SignableTransaction::into_signed(tx_seismic, signature).into();

    let mut tx_env = TxEnv::default();
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let result = unit_test_context.evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender);
    assert!(matches!(result, Err(EVMError::Database(EnclaveError::DecryptionError))));
}
