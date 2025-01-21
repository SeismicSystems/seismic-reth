// The motivation of this file is to include unit tests for seismic features that are currently
// scattered across the codebase

mod seismic_transaction_tests {
    use alloy_consensus::{SignableTransaction, TxSeismic};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{
        hex_literal, keccak256, Address, Bytes, FixedBytes, PrimitiveSignature, U256,
    };
    use arbitrary::Arbitrary;
    use core::str::FromStr;
    use enr::EnrKey;
    use k256::ecdsa::SigningKey;
    use reth_chainspec::MAINNET;
    use reth_evm::ConfigureEvmEnv;
    use reth_node_ethereum::EthEvmConfig;
    use reth_primitives::{Transaction, TransactionSigned};
    use reth_revm::primitives::{EVMError, TxEnv};
    use reth_rpc_eth_types::utils::recover_raw_transaction;
    use reth_tee::TeeError;
    use secp256k1::ecdh::SharedSecret;
    use seismic_node::utils::{
        start_mock_tee_server,
        test_utils::{IntegrationTestContext, UnitTestContext},
    };
    use tee_service_api::{aes_encrypt, derive_aes_key, get_sample_secp256k1_pk};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_seismic_transactions() {
        start_mock_tee_server().await;
        sign();
        // test_encoding_decoding_signed_seismic_tx();
        // test_fill_tx_env();
        // test_fill_tx_env_decryption_error();
        // test_fill_tx_env_seismic_public_key_recovery_error();
    }

    fn sign() {
        let tx = UnitTestContext::get_seismic_tx();

        let signature = UnitTestContext::sign_seismic_tx(&tx);
        println!("signature: {:?}", signature);
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
        tx_seismic.encryption_pubkey = FixedBytes::from_slice(
            &UnitTestContext::get_wrong_private_key().public().to_sec1_bytes(),
        );

        let signature = UnitTestContext::sign_seismic_tx(&tx_seismic);
        let tx_signed: TransactionSigned =
            SignableTransaction::into_signed(tx_seismic, signature).into();

        let mut tx_env = TxEnv::default();
        let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let result = evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender);
        assert!(matches!(result, Err(EVMError::Database(TeeError::DecryptionError))))
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

        assert!(matches!(result, Err(EVMError::Database(TeeError::PublicKeyRecoveryError))));
    }
}
