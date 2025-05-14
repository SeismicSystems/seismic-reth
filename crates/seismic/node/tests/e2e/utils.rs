use alloy_eips::{eip2930::AccessListItem, eip7702::Authorization, BlockId, BlockNumberOrTag};
use alloy_primitives::{bytes, Address, B256, U256};
use alloy_provider::{
    network::{
        Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder, TransactionBuilder7702,
    },
    Provider, ProviderBuilder, SendableTx,
};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer::SignerSync;
use rand::{seq::SliceRandom, Rng};
use reth_e2e_test_utils::{wallet::Wallet, NodeHelperType, TmpDB};
use reth_ethereum_engine_primitives::PayloadBuilderAttributes;
use reth_ethereum_primitives::TxType;
use reth_node_api::NodeTypesWithDBAdapter;
use reth_node_ethereum::EthereumNode;
use reth_provider::FullProvider;

/// Helper function to create a new eth payload attributes
pub(crate) fn eth_payload_attributes(timestamp: u64) -> PayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    PayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Advances node by producing blocks with random transactions.
pub(crate) async fn advance_with_random_transactions<Provider>(
    node: &mut NodeHelperType<EthereumNode, Provider>,
    num_blocks: usize,
    rng: &mut impl Rng,
    finalize: bool,
) -> eyre::Result<()>
where
    Provider: FullProvider<NodeTypesWithDBAdapter<EthereumNode, TmpDB>>,
{
    let provider = ProviderBuilder::new().on_http(node.rpc_url());
    let signers = Wallet::new(1).with_chain_id(provider.get_chain_id().await?).gen();

    // simple contract which writes to storage on any call
    let dummy_bytecode = bytes!("6080604052348015600f57600080fd5b50602880601d6000396000f3fe4360a09081523360c0526040608081905260e08152902080805500fea164736f6c6343000810000a");
    let mut call_destinations = signers.iter().map(|s| s.address()).collect::<Vec<_>>();

    for _ in 0..num_blocks {
        let tx_count = rng.gen_range(1..20);

        let mut pending = vec![];
        for _ in 0..tx_count {
            let signer = signers.choose(rng).unwrap();
            let tx_type = TxType::try_from(rng.gen_range(0..=4) as u64).unwrap();

            let nonce = provider
                .get_transaction_count(signer.address())
                .block_id(BlockId::Number(BlockNumberOrTag::Pending))
                .await?;

            let mut tx =
                TransactionRequest::default().with_from(signer.address()).with_nonce(nonce);

            let should_create =
                rng.gen::<bool>() && tx_type != TxType::Eip4844 && tx_type != TxType::Eip7702;
            if should_create {
                tx = tx.into_create().with_input(dummy_bytecode.clone());
            } else {
                tx = tx.with_to(*call_destinations.choose(rng).unwrap()).with_input(
                    (0..rng.gen_range(0..10000)).map(|_| rng.gen()).collect::<Vec<u8>>(),
                );
            }

            if matches!(tx_type, TxType::Legacy | TxType::Eip2930) {
                tx = tx.with_gas_price(provider.get_gas_price().await?);
            }

            if rng.gen::<bool>() || tx_type == TxType::Eip2930 {
                tx = tx.with_access_list(
                    vec![AccessListItem {
                        address: *call_destinations.choose(rng).unwrap(),
                        storage_keys: (0..rng.gen_range(0..100)).map(|_| rng.gen()).collect(),
                    }]
                    .into(),
                );
            }

            if tx_type == TxType::Eip7702 {
                let signer = signers.choose(rng).unwrap();
                let auth = Authorization {
                    chain_id: U256::from(provider.get_chain_id().await?),
                    address: *call_destinations.choose(rng).unwrap(),
                    nonce: provider
                        .get_transaction_count(signer.address())
                        .block_id(BlockId::Number(BlockNumberOrTag::Pending))
                        .await?,
                };
                let sig = signer.sign_hash_sync(&auth.signature_hash())?;
                tx = tx.with_authorization_list(vec![auth.into_signed(sig)])
            }

            let gas = provider
                .estimate_gas(tx.clone())
                .block(BlockId::Number(BlockNumberOrTag::Pending))
                .await
                .unwrap_or(1_000_000);

            tx.set_gas_limit(gas);

            let SendableTx::Builder(tx) = provider.fill(tx).await? else { unreachable!() };
            let tx =
                NetworkWallet::<Ethereum>::sign_request(&EthereumWallet::new(signer.clone()), tx)
                    .await?;

            pending.push(provider.send_tx_envelope(tx).await?);
        }

        let payload = node.build_and_submit_payload().await?;
        if finalize {
            node.update_forkchoice(payload.block().hash(), payload.block().hash()).await?;
        } else {
            let last_safe =
                provider.get_block_by_number(BlockNumberOrTag::Safe).await?.unwrap().header.hash;
            node.update_forkchoice(last_safe, payload.block().hash()).await?;
        }

        for pending in pending {
            let receipt = pending.get_receipt().await?;
            if let Some(address) = receipt.contract_address {
                call_destinations.push(address);
            }
        }
    }

    Ok(())
}

/// Test utils for the seismic rpc api
#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::ext::test_address;
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
    use jsonrpsee_core::server::Methods;
    use k256::ecdsa::SigningKey;
    use reth_chainspec::MAINNET;
    use reth_e2e_test_utils::transaction::TransactionTestContext;
    use reth_enclave::MockEnclaveServer;
    use reth_network_api::noop::NoopNetwork;
    use reth_payload_builder::EthPayloadBuilderAttributes;
    use reth_primitives::TransactionSigned;
    use reth_provider::StateProviderFactory;
    use reth_rpc::EthApi;
    use reth_rpc_builder::{
        RpcModuleSelection, RpcServerConfig, RpcServerHandle, TransportRpcModuleConfig,
    };
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
    use std::{path::PathBuf, process::Stdio, sync::Arc};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
        sync::mpsc,
    };
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
