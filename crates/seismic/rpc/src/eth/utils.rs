//! Utils for testing the seismic rpc api

use alloy_rpc_types::{BlockTransactions, TransactionRequest};
use reth_primitives::RecoveredTx;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_eth_api::{helpers::FullEthApi, RpcBlock};
use reth_rpc_eth_types::{EthApiError, EthResult};
use seismic_alloy_consensus::{Decodable712, TypedDataRequest};

/// Override the request for seismic calls
pub fn seismic_override_call_request(request: &mut TransactionRequest) {
    // If user calls with the standard (unsigned) eth_call,
    // then disregard whatever they put in the from field
    // They will still be able to read public contract functions,
    // but they will not be able to spoof msg.sender in these calls
    request.from = None;
    request.gas_price = None; // preventing InsufficientFunds error
    request.max_fee_per_gas = None; // preventing InsufficientFunds error
    request.max_priority_fee_per_gas = None; // preventing InsufficientFunds error
    request.max_fee_per_blob_gas = None; // preventing InsufficientFunds error
    request.value = None; // preventing InsufficientFunds error
}

/// Recovers a [`SignedTransaction`] from a typed data request.
///
/// This is a helper function that returns the appropriate RPC-specific error if the input data is
/// malformed.
///
/// See [`alloy_eips::eip2718::Decodable2718::decode_2718`]
pub fn recover_typed_data_request<T: SignedTransaction>(
    mut data: &TypedDataRequest,
) -> EthResult<RecoveredTx<T>> {
    let transaction =
        T::decode_712(&mut data).map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;

    transaction.try_into_recovered().or(Err(EthApiError::InvalidTransactionSignature))
}

/// Test utils for the seismic rpc api
#[cfg(test)]
pub mod test_utils {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEnvelope, TypedTransaction};
    use alloy_dyn_abi::TypedData;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{
        aliases::U96, hex_literal, Address, Bytes, PrimitiveSignature, TxKind, B256, U256,
    };
    use alloy_rpc_types::{
        engine::PayloadAttributes, Block, Header, Transaction, TransactionInput, TransactionReceipt,
    };
    use alloy_rpc_types_eth::TransactionRequest;
    use alloy_signer_local::PrivateKeySigner;
    use core::str::FromStr;
    use enr::EnrKey;
    use jsonrpsee::http_client::HttpClient;
    use k256::ecdsa::SigningKey;
    use reth_e2e_test_utils::transaction::TransactionTestContext;
    use reth_enclave::MockEnclaveServer;
    use reth_network_api::noop::NoopNetwork;
    use reth_payload_builder::EthPayloadBuilderAttributes;
    use reth_primitives::TransactionSigned;
    use reth_provider::StateProviderFactory;
    use reth_rpc::EthApi;
    use reth_rpc_eth_api::EthApiClient;
    use reth_seismic_chainspec::SEISMIC_DEV;
    use reth_seismic_primitives::{SeismicPrimitives, SeismicTransactionSigned};
    use reth_transaction_pool::test_utils::TestPool;
    use secp256k1::{PublicKey, SecretKey};
    use seismic_alloy_consensus::{
        SeismicTxEnvelope::Seismic, SeismicTypedTransaction, TxSeismic, TxSeismicElements,
        TypedDataRequest,
    };
    use seismic_alloy_rpc_types::SeismicTransactionRequest;
    use serde_json::Value;
    use std::{path::PathBuf, process::Stdio};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
        sync::mpsc,
    };
    use jsonrpsee_core::server::Methods;
    use reth_rpc_builder::RpcServerHandle;
    use reth_rpc_builder::TransportRpcModuleConfig;
    use reth_rpc_builder::RpcModuleSelection;
    use std::sync::Arc;
    use reth_chainspec::MAINNET;
    use reth_rpc_builder::RpcServerConfig;
    use crate::ext::test_address;
    // use reth_seismic_evm::engine::SeismicEngineValidator;

    /// Get the nonce from the client
    pub async fn get_nonce(client: &HttpClient, address: Address) -> u64 {
        let nonce =
            EthApiClient::<Transaction, Block, TransactionReceipt, Header>::transaction_count(
                client, address, None,
            )
            .await
            .unwrap();
        nonce.wrapping_to::<u64>()
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

    // /// Create a seismic transaction
    // pub async fn get_signed_seismic_tx_bytes(
    //     sk_wallet: &PrivateKeySigner,
    //     nonce: u64,
    //     to: TxKind,
    //     chain_id: u64,
    //     plaintext: Bytes,
    // ) -> Bytes {
    //     let mut tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id,
    // plaintext).await;     let signed_inner =
    // TransactionTestContext::sign_tx(sk_wallet.clone(), tx.inner).await;     tx.inner =
    // signed_inner.into();     <TxEnvelope as Encodable2718>::encoded_2718(&tx).into()
    // }

    // /// Get an unsigned seismic transaction typed data
    // pub async fn get_unsigned_seismic_tx_typed_data(
    //     sk_wallet: &PrivateKeySigner,
    //     nonce: u64,
    //     to: TxKind,
    //     chain_id: u64,
    //     decrypted_input: Bytes,
    // ) -> TypedData {
    //     let tx_request =
    //         get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id,
    // decrypted_input).await;     let typed_tx =
    // tx_request.inner.build_consensus_tx().unwrap();     match typed_tx {
    //         SeismicTypedTransaction::Seismic(seismic) => seismic.eip712_to_type_data(),
    //         _ => panic!("Typed transaction is not a seismic transaction"),
    //     }
    // }

    // /// Create a seismic transaction with typed data
    // pub async fn get_signed_seismic_tx_typed_data(
    //     sk_wallet: &PrivateKeySigner,
    //     nonce: u64,
    //     to: TxKind,
    //     chain_id: u64,
    //     plaintext: Bytes,
    // ) -> TypedDataRequest {
    //     let mut tx: SeismicTransactionRequest = get_unsigned_seismic_tx_request(sk_wallet, nonce,
    // to, chain_id, plaintext).await;     tx.seismic_elements.unwrap().message_version = 2;
    //     let signed_inner = TransactionTestContext::sign_tx(sk_wallet.clone(), tx.inner).await;

    //     tx.inner = signed_inner.into();
    //     tx

    //     // let tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id,
    // plaintext).await;     // tx.seismic_elements.unwrap().message_version = 2;
    //     // let signed = TransactionTestContext::sign_tx(sk_wallet.clone(), tx).await;

    //     // match signed {
    //     //     Seismic(tx) => tx.into(),
    //     //     _ => panic!("Signed transaction is not a seismic transaction"),
    //     // }
    // }

    /// Get the network public key
    pub fn get_network_public_key() -> PublicKey {
        MockEnclaveServer::get_public_key()
    }

    /// Encrypt plaintext using network public key and client private key
    pub fn get_ciphertext() -> Bytes {
        let encrypted_data = client_encrypt(&get_plaintext());
        encrypted_data
    }

    /// Encrypt plaintext using network public key and client private key
    pub fn client_encrypt(plaintext: &Bytes) -> Bytes {
        get_seismic_elements()
            .client_encrypt(plaintext, &get_network_public_key(), &get_encryption_private_key())
            .unwrap()
    }

    /// Decrypt ciphertext using network public key and client private key
    pub fn client_decrypt(ciphertext: &Bytes) -> Bytes {
        get_seismic_elements()
            .client_decrypt(ciphertext, &get_network_public_key(), &get_encryption_private_key())
            .unwrap()
    }

    /// Get the encryption private key
    pub fn get_encryption_private_key() -> SecretKey {
        let private_key_bytes =
            hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        SecretKey::from_slice(&private_key_bytes).expect("Invalid private key")
    }

    /// Get the encryption nonce
    pub fn get_encryption_nonce() -> U96 {
        U96::MAX
    }

    /// Get the seismic elements
    pub fn get_seismic_elements() -> TxSeismicElements {
        TxSeismicElements {
            encryption_pubkey: get_encryption_private_key().public(),
            encryption_nonce: get_encryption_nonce(),
            message_version: 0,
        }
    }

    /// Get a wrong private key
    pub fn get_wrong_private_key() -> SecretKey {
        let private_key_bytes =
            hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1e");
        SecretKey::from_slice(&private_key_bytes).expect("Invalid private key")
    }

    /// Get the signing private key
    pub fn get_signing_private_key() -> SigningKey {
        let private_key_bytes =
            hex_literal::hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let signing_key =
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
        signing_key
    }

    /// Get the plaintext for a seismic transaction
    pub fn get_plaintext() -> Bytes {
        Bytes::from_str("24a7f0b7000000000000000000000000000000000000000000000000000000000000000b")
            .unwrap()
    }

    /// Get a seismic transaction
    pub fn get_seismic_tx() -> TxSeismic {
        let ciphertext = get_ciphertext();
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
            seismic_elements: get_seismic_elements(),
        }
    }

    /// Get the encoding of a signed seismic transaction
    pub fn get_signed_seismic_tx_encoding() -> Vec<u8> {
        let signed_tx = get_signed_seismic_tx();
        let mut encoding = Vec::new();

        signed_tx.encode_2718(&mut encoding);
        encoding
    }

    /// Sign a seismic transaction
    pub fn sign_seismic_tx(tx: &TxSeismic) -> PrimitiveSignature {
        let _signature = get_signing_private_key()
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

    /// Get a signed seismic transaction
    pub fn get_signed_seismic_tx() -> SeismicTransactionSigned {
        let tx = get_seismic_tx();
        let signature = sign_seismic_tx(&tx);
        SignableTransaction::into_signed(tx, signature).into()
    }

    // /// Launches a new server with http only with the given modules
    // pub async fn launch_http(modules: impl Into<Methods>) -> RpcServerHandle {
    //     let builder = test_rpc_builder();
    //     let mut server = builder.build(
    //         TransportRpcModuleConfig::set_http(RpcModuleSelection::Standard),
    //         Box::new(EthApi::with_spawner),
    //         Arc::new(SeismicEngineValidator::new(MAINNET.clone())),
    //     );
    //     server.replace_configured(modules).unwrap();
    //     RpcServerConfig::http(Default::default())
    //         .with_http_address(test_address())
    //         .start(&server)
    //         .await
    //         .unwrap()
    // }

    // /// Builds a test eth api
    // pub fn build_test_seismic_eth_api<
    //     P: BlockReaderIdExt<
    //             Block = SeismicPrimitives::Block,
    //             Receipt = SeismicPrimitives::Receipt,
    //             Header = SeismicPrimitives::Header,
    //         > + BlockReader
    //         + ChainSpecProvider<ChainSpec = ChainSpec>
    //         + EvmEnvProvider
    //         + StateProviderFactory
    //         + Unpin
    //         + Clone
    //         + 'static,
    // >(
    //     provider: P,
    // ) -> EthApi<P, TestPool, NoopNetwork, EthEvmConfig> {
    // let evm_config = EthEvmConfig::new(provider.chain_spec());
    // let cache = EthStateCache::spawn(provider.clone(), Default::default());
    // let fee_history_cache = FeeHistoryCache::new(FeeHistoryCacheConfig::default());

    // EthApi::new(
    //     provider.clone(),
    //     testing_pool(),
    //     NoopNetwork::default(),
    //     cache.clone(),
    //     GasPriceOracle::new(provider, Default::default(), cache),
    //     GasCap::default(),
    //     DEFAULT_MAX_SIMULATE_BLOCKS,
    //     DEFAULT_ETH_PROOF_WINDOW,
    //     BlockingTaskPool::build().expect("failed to build tracing pool"),
    //     fee_history_cache,
    //     evm_config,
    //     DEFAULT_PROOF_PERMITS,
    // )
    //     todo!()
    // }
}
