//! Test utils for seismic primitives, e.g. SeismicTransactionSigned

use crate::SeismicTransactionSigned;
use alloy_consensus::SignableTransaction;
use alloy_dyn_abi::TypedData;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{
    aliases::U96, hex_literal, Address, Bytes, PrimitiveSignature, TxKind, U256,
};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use core::str::FromStr;
use enr::EnrKey;
use k256::ecdsa::SigningKey;
use reth_enclave::MockEnclaveServer;
use secp256k1::{PublicKey, SecretKey};
use seismic_alloy_consensus::{
    SeismicTxEnvelope, SeismicTypedTransaction, TxSeismic, TxSeismicElements, TypedDataRequest,
};
use seismic_alloy_rpc_types::SeismicTransactionRequest;

/// Get the network public key
pub fn get_network_public_key() -> PublicKey {
    MockEnclaveServer::get_public_key()
}

/// Get the client's sk for tx io
pub fn get_client_io_sk() -> SecretKey {
    let private_key_bytes =
        hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    SecretKey::from_slice(&private_key_bytes).expect("Invalid private key")
}

/// Get the client's signing private key
pub fn get_signing_private_key() -> SigningKey {
    let private_key_bytes =
        hex_literal::hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
    signing_key
}

/// Get a wrong private secp256k1 key
pub fn get_wrong_private_key() -> SecretKey {
    let private_key_bytes =
        hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1e");
    SecretKey::from_slice(&private_key_bytes).expect("Invalid private key")
}

/// Get the encryption nonce
pub fn get_encryption_nonce() -> U96 {
    U96::MAX
}

/// Get the seismic elements
pub fn get_seismic_elements() -> TxSeismicElements {
    TxSeismicElements {
        encryption_pubkey: get_client_io_sk().public(),
        encryption_nonce: get_encryption_nonce(),
        message_version: 0,
    }
}

/// Encrypt plaintext using network public key and client private key
pub fn client_encrypt(plaintext: &Bytes) -> Bytes {
    get_seismic_elements()
        .client_encrypt(plaintext, &get_network_public_key(), &get_client_io_sk())
        .unwrap()
}

/// Decrypt ciphertext using network public key and client private key
pub fn client_decrypt(ciphertext: &Bytes) -> Bytes {
    get_seismic_elements()
        .client_decrypt(ciphertext, &get_network_public_key(), &get_client_io_sk())
        .unwrap()
}

/// Get the plaintext for a seismic transaction
pub fn get_plaintext() -> Bytes {
    Bytes::from_str("24a7f0b7000000000000000000000000000000000000000000000000000000000000000b")
        .unwrap()
}

/// Encrypt plaintext using network public key and client private key
pub fn get_ciphertext() -> Bytes {
    let encrypted_data = client_encrypt(&get_plaintext());
    encrypted_data
}

/// Get a seismic transaction
pub fn get_seismic_tx() -> TxSeismic {
    let ciphertext = get_ciphertext();
    TxSeismic {
        chain_id: 5123, // seismic chain id
        nonce: 1,
        gas_price: 20000000000,
        gas_limit: 210000,
        to: alloy_primitives::TxKind::Call(
            Address::from_str("0x5fbdb2315678afecb367f032d93f642f64180aa3").unwrap(),
        ),
        value: U256::ZERO,
        input: Bytes::copy_from_slice(&ciphertext),
        seismic_elements: get_seismic_elements(),
    }
}

/// Sign a seismic transaction
pub fn sign_seismic_tx(tx: &TxSeismic, signing_sk: &SigningKey) -> PrimitiveSignature {
    let _signature = signing_sk
        .clone()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
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

/// signes a [`SeismicTypedTransaction`] using the provided [`SigningKey`]
pub fn sign_seismic_typed_tx(typed_data: &SeismicTypedTransaction, signing_sk: &SigningKey) -> PrimitiveSignature {
    let sig_hash = typed_data.signature_hash();
    let sig = signing_sk.sign_prehash_recoverable(&sig_hash.as_slice()).unwrap();
    let recoverid = sig.1;

    let signature = PrimitiveSignature::new(
        U256::from_be_slice(sig.0.r().to_bytes().as_slice()),
        U256::from_be_slice(sig.0.s().to_bytes().as_slice()),
        recoverid.is_y_odd(),
    );
    signature
}

/// Get a signed seismic transaction
pub fn get_signed_seismic_tx() -> SeismicTransactionSigned {
    let signing_sk = get_signing_private_key();
    let tx = get_seismic_tx();
    let signature = sign_seismic_tx(&tx, &signing_sk);
    SignableTransaction::into_signed(tx, signature).into()
}

/// Get the encoding of a signed seismic transaction
pub fn get_signed_seismic_tx_encoding() -> Vec<u8> {
    let signed_tx = get_signed_seismic_tx();
    let mut encoding = Vec::new();

    signed_tx.encode_2718(&mut encoding);
    encoding
}

/// Get an unsigned seismic transaction request
pub async fn get_unsigned_seismic_tx_request(
    sk_wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    plaintext: Bytes,
) -> SeismicTransactionRequest {
    SeismicTransactionRequest {
        inner: TransactionRequest {
            from: Some(sk_wallet.address()),
            nonce: Some(nonce),
            value: Some(U256::from(0)),
            to: Some(to),
            gas: Some(6000000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(client_encrypt(&plaintext)), data: None },
            transaction_type: Some(TxSeismic::TX_TYPE),
            ..Default::default()
        },
        seismic_elements: Some(get_seismic_elements()),
    }
}

/// Signs an arbitrary [`TransactionRequest`] using the provided wallet
pub async fn sign_tx(wallet: PrivateKeySigner, tx: SeismicTransactionRequest) -> SeismicTxEnvelope {
    let signer = EthereumWallet::from(wallet);
    <SeismicTransactionRequest as TransactionBuilder<seismic_alloy_network::Seismic>>::build(
        tx, &signer,
    )
    .await
    .unwrap()
}

/// Create a seismic transaction
pub async fn get_signed_seismic_tx_bytes(
    sk_wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    plaintext: Bytes,
) -> Bytes {
    let tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, plaintext).await;
    let signed_inner = sign_tx(sk_wallet.clone(), tx).await;
    <SeismicTxEnvelope as Encodable2718>::encoded_2718(&signed_inner).into()
}

/// Get an unsigned seismic transaction typed data
pub async fn get_unsigned_seismic_tx_typed_data(
    sk_wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    decrypted_input: Bytes,
) -> TypedData {
    let tx_request =
        get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, decrypted_input).await;
    let typed_tx = tx_request.build_typed_tx().unwrap();
    match typed_tx {
        SeismicTypedTransaction::Seismic(seismic) => seismic.eip712_to_type_data(),
        _ => panic!("Typed transaction is not a seismic transaction"),
    }
}

/// Create a seismic transaction with typed data
pub async fn get_signed_seismic_tx_typed_data(
    sk_wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    plaintext: Bytes,
) -> TypedDataRequest {
    let tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, plaintext).await;
    tx.seismic_elements.unwrap().message_version = 2;
    let signed = sign_tx(sk_wallet.clone(), tx).await;

    match signed {
        SeismicTxEnvelope::Seismic(tx) => tx.into(),
        _ => panic!("Signed transaction is not a seismic transaction"),
    }
}
