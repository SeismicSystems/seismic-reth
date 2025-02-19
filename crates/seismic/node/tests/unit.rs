//! The motivation of this file is to include unit tests for seismic features that are currently
// scattered across the codebase
use alloy_consensus::{SignableTransaction, TxSeismic};
use alloy_primitives::{keccak256, Address, FixedBytes, PrimitiveSignature};
use arbitrary::Arbitrary;
use core::str::FromStr;
use enr::EnrKey;
use reth_enclave::EnclaveError;
use reth_evm::ConfigureEvmEnv;
use reth_primitives::{Transaction, TransactionSigned};
use reth_revm::primitives::{EVMError, TxEnv};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use seismic_node::utils::test_utils::{start_mock_enclave_server_random_port, UnitTestContext};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seismic_transactions() {
    start_mock_enclave_server_random_port().await; // avoid port collision with other tests when running them in parallel
    test_fill_tx_env();
    test_fill_tx_env_decryption_error();
    test_encoding_decoding_signed_seismic_tx();
    test_fill_tx_env_seismic_public_key_recovery_error();
}

// This route is used to test the encoding and decoding of the signed seismic tx
fn test_encoding_decoding_signed_seismic_tx() {
    let encoding = UnitTestContext::get_signed_seismic_tx_encoding();
    let decoded_signed_tx =
        recover_raw_transaction::<TransactionSigned>(&encoding).unwrap().as_signed().clone();
    assert_eq!(decoded_signed_tx, UnitTestContext::get_signed_seismic_tx());
}

fn test_fill_tx_env() {
    let evm_config = UnitTestContext::get_evm_config();
    let tx_signed = UnitTestContext::get_signed_seismic_tx();
    let mut tx_env = TxEnv::default();
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let _ = evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender).unwrap();
    assert!(UnitTestContext::get_plaintext() == tx_env.data)
}

// Decryption error is expected when the encryption public key in transaction is invalid
fn test_fill_tx_env_decryption_error() {
    let evm_config = UnitTestContext::get_evm_config();
    let mut tx_seismic = UnitTestContext::get_seismic_tx();
    tx_seismic.encryption_pubkey =
        FixedBytes::from_slice(&UnitTestContext::get_wrong_private_key().public().to_sec1_bytes());

    let signature = UnitTestContext::sign_seismic_tx(&tx_seismic);
    let tx_signed: TransactionSigned =
        SignableTransaction::into_signed(tx_seismic, signature).into();

    let mut tx_env = TxEnv::default();
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let result = evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender);
    assert!(matches!(result, Err(EVMError::Database(EnclaveError::DecryptionError))))
}

fn test_fill_tx_env_seismic_public_key_recovery_error() {
    let evm_config = UnitTestContext::get_evm_config();
    let mut unstructured = arbitrary::Unstructured::new(&[0u8; 32]);
    let tx = Transaction::Seismic(TxSeismic::arbitrary(&mut unstructured).unwrap());
    let signature = PrimitiveSignature::arbitrary(&mut unstructured).unwrap();
    let hash = &mut Vec::new();
    tx.eip2718_encode(&signature, hash);
    let hash = keccak256(hash);
    let tx_signed = TransactionSigned::new(tx, signature, hash);
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let mut tx_env = TxEnv::default();

    let result = evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender);

    assert!(matches!(result, Err(EVMError::Database(EnclaveError::PublicKeyRecoveryError))));
}
