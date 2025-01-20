// The motivation of this file is to include unit tests for seismic features that are currently
// scattered across the codebase

#[cfg(test)]
mod seismic_transaction_tests {
    use alloy_consensus::{SignableTransaction, TxSeismic};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{
        hex, hex_literal, keccak256, Address, Bytes, FixedBytes, PrimitiveSignature, U256,
    };
    use arbitrary::Arbitrary;
    use core::str::FromStr;
    use enr::EnrKey;
    use k256::{
        ecdsa::{signature::SignerMut, SigningKey, VerifyingKey},
        elliptic_curve::sec1::ToEncodedPoint,
    };
    use reth_chainspec::MAINNET;
    use reth_evm::ConfigureEvmEnv;
    use reth_node_ethereum::EthEvmConfig;
    use reth_primitives::{Transaction, TransactionSigned};
    use reth_revm::primitives::{EVMError, TxEnv};
    use reth_rpc_eth_types::utils::recover_raw_transaction;
    use reth_tee::{encrypt, TeeError, TeeHttpClient};
    use secp256k1::{
        ecdh::SharedSecret,
        rand::{self, RngCore},
    };
    use seismic_node::utils::start_mock_tee_server;
    use tee_service_api::{aes_encrypt, derive_aes_key, get_sample_secp256k1_pk};

    use super::*;

    #[tokio::test]
    async fn test_seismic_transactions() {
        start_mock_tee_server().await;
        test_encoding_decoding_signed_seismic_tx();
        // test_fill_tx_env_decryption_error(&get_evm_config(), get_signed_seismic_tx_encoding());
        test_fill_tx_env_seismic_public_key_recovery_error();
    }

    fn get_client_side_encryption() -> Vec<u8> {
        let ecdh_sk = get_sample_secp256k1_pk();
        let signing_key_bytes = get_encryption_private_key().to_bytes();
        let signing_key_secp256k1 =
            secp256k1::SecretKey::from_slice(&signing_key_bytes).expect("Invalid secret key");
        let shared_secret = SharedSecret::new(&ecdh_sk, &signing_key_secp256k1);

        let aes_key = derive_aes_key(&shared_secret).unwrap();
        let encrypted_data = aes_encrypt(&aes_key, get_plaintext().as_slice(), 1).unwrap();
        encrypted_data
    }

    fn get_evm_config() -> EthEvmConfig {
        EthEvmConfig::new(MAINNET.clone())
    }

    fn get_encryption_private_key() -> SigningKey {
        let private_key_bytes =
            hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key")
    }

    fn get_signing_private_key() -> SigningKey {
        let private_key_bytes =
            hex_literal::hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let signing_key =
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
        signing_key
    }

    fn get_plaintext() -> Vec<u8> {
        hex_literal::hex!(
            "24a7f0b7000000000000000000000000000000000000000000000000000000000000000b"
        )
        .to_vec()
    }

    fn get_seismic_tx() -> TxSeismic {
        let ciphertext = get_client_side_encryption();
        TxSeismic {
            chain_id: 1337,
            nonce: 1,
            gas_price: 20000000000,
            gas_limit: 210000,
            to: alloy_primitives::TxKind::Call(
                Address::from_str("0x5fbdb2315678afecb367f032d93f642f64180aa3").unwrap(),
            ),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(&ciphertext),
            encryption_pubkey: FixedBytes::from_slice(
                &get_encryption_private_key().public().to_sec1_bytes(),
            ),
        }
    }

    fn get_signed_seismic_tx_encoding() -> Vec<u8> {
        let signed_tx = get_signed_seismic_tx();
        let mut encoding = Vec::new();

        signed_tx.encode_2718(&mut encoding);
        encoding
    }

    fn sign_seismic_tx(tx: &TxSeismic) -> PrimitiveSignature {
        let _signature = get_signing_private_key()
            .clone()
            .sign_recoverable(tx.signature_hash().as_slice())
            .expect("Failed to sign");

        let recoverid = _signature.1;
        let _signature = _signature.0;

        let signature = PrimitiveSignature::new(
            U256::from_be_slice(_signature.r().to_bytes().as_slice()),
            U256::from_be_slice(_signature.s().to_bytes().as_slice()),
            recoverid.is_y_odd(),
        );

        signature
    }

    fn get_signed_seismic_tx() -> TransactionSigned {
        let tx = get_seismic_tx();
        let signature = sign_seismic_tx(&tx);
        SignableTransaction::into_signed(tx, signature).into()
    }

    // This route is used to test the encoding and decoding of the signed seismic tx
    fn test_encoding_decoding_signed_seismic_tx() {
        let encoding = get_signed_seismic_tx_encoding();
        let decoded_signed_tx =
            recover_raw_transaction::<TransactionSigned>(&encoding).unwrap().as_signed().clone();
        assert_eq!(decoded_signed_tx, get_signed_seismic_tx());
    }

    fn test_fill_tx_env_seismic_public_key_recovery_error() {
        let evm_config = get_evm_config();
        let mut unstructured = arbitrary::Unstructured::new(&[0u8; 32]);
        let tx = Transaction::Seismic(TxSeismic::arbitrary(&mut unstructured).unwrap());
        let signature = PrimitiveSignature::arbitrary(&mut unstructured).unwrap();
        let hash = &mut Vec::new();
        tx.eip2718_encode(&signature, hash);
        let hash = keccak256(hash);
        let tx_signed = TransactionSigned::new(tx, signature, hash);
        let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let tee = TeeHttpClient::default();
        let mut tx_env = TxEnv::default();

        let result = evm_config.fill_tx_env(&mut tx_env, &tx_signed, sender);

        assert!(matches!(result, Err(EVMError::Database(TeeError::PublicKeyRecoveryError))));
    }
}
