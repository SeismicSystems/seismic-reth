//! The motivation of this file is to include unit tests for seismic features that are currently
// scattered across the codebase
use alloy_consensus::SignableTransaction;
use alloy_primitives::Address;
use core::str::FromStr;
use enr::EnrKey;
use reth_chainspec::{ChainSpec, SEISMIC_DEV};
use reth_enclave::{start_mock_enclave_server_random_port, EnclaveClient, EnclaveError};
use reth_evm::ConfigureEvmEnv;
use reth_node_ethereum::EthEvmConfig;
use reth_primitives::TransactionSigned;
use reth_revm::primitives::{EVMError, TxEnv};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use seismic_node::utils::test_utils::{
    get_plaintext, get_seismic_tx, get_signed_seismic_tx, get_signed_seismic_tx_encoding,
    get_wrong_private_key, sign_seismic_tx,
};
use std::sync::Arc;

#[derive(Debug)]
/// Artificats for unit tests
pub struct EvmConfigTest {
    /// The enclave client
    pub enclave_client: EnclaveClient,
    /// The evm config
    pub evm_config: EthEvmConfig,
    /// The chain spec
    pub chain_spec: Arc<ChainSpec>,
}
impl EvmConfigTest {
    /// Create a new unit test context
    pub async fn new() -> Self {
        let enclave_client = start_mock_enclave_server_random_port().await;
        let chain_spec = SEISMIC_DEV.clone();
        let evm_config =
            EthEvmConfig::new_with_enclave_client(chain_spec.clone(), enclave_client.clone());

        Self { enclave_client, evm_config, chain_spec }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_seismic_transactions() {
    let unit_test_context = EvmConfigTest::new().await;
    test_fill_tx_env(&unit_test_context);
    test_fill_tx_env_decryption_error(&unit_test_context);
    test_encoding_decoding_signed_seismic_tx();
}

// This route is used to test the encoding and decoding of the signed seismic tx
fn test_encoding_decoding_signed_seismic_tx() {
    let encoding = get_signed_seismic_tx_encoding();
    let decoded_signed_tx =
        recover_raw_transaction::<TransactionSigned>(&encoding).unwrap().as_signed().clone();
    assert_eq!(decoded_signed_tx, get_signed_seismic_tx());
}

fn test_fill_tx_env(unit_test_context: &EvmConfigTest) {
    let tx_signed = get_signed_seismic_tx();
    let mut tx_env = TxEnv::default();
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let _ = unit_test_context.evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender).unwrap();
    assert!(get_plaintext() == tx_env.data)
}

// Decryption error is expected when the encryption public key in transaction is invalid
fn test_fill_tx_env_decryption_error(unit_test_context: &EvmConfigTest) {
    let mut tx_seismic = get_seismic_tx();
    tx_seismic.seismic_elements.encryption_pubkey = get_wrong_private_key().public();

    let signature = sign_seismic_tx(&tx_seismic);
    let tx_signed: TransactionSigned =
        SignableTransaction::into_signed(tx_seismic, signature).into();

    let mut tx_env = TxEnv::default();
    let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let result = unit_test_context.evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender);
    assert!(matches!(result, Err(EVMError::Database(EnclaveError::DecryptionError))));
}
