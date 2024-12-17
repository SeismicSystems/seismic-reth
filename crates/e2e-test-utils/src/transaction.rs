use alloy_consensus::{EnvKzgSettings, SidecarBuilder, SimpleCoder, TxEip4844Variant, TxEnvelope};
use alloy_network::{
    eip2718::Encodable2718, Ethereum, EthereumWallet, TransactionBuilder, TransactionBuilder4844,
};
use alloy_rlp::Encodable;
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use eyre::Ok;
use reth_primitives::{
    hex, Address, Bytes, Transaction, TransactionSigned, TxKind, TxLegacy, TxSeismic, B256, U256,
};
use reth_tee::{mock::MockWallet, WalletAPI};
use secp256k1::SecretKey;

/// Helper for transaction operations
#[derive(Debug)]
pub struct TransactionTestContext;

impl TransactionTestContext {
    /// Creates a static transfer and signs it, returning bytes
    pub async fn transfer_tx(chain_id: u64, wallet: PrivateKeySigner) -> TxEnvelope {
        let tx = tx(chain_id, None, 0);
        Self::sign_tx(wallet, tx).await
    }

    /// Creates a static transfer and signs it, returning bytes
    pub async fn transfer_tx_bytes(chain_id: u64, wallet: PrivateKeySigner) -> Bytes {
        let signed = Self::transfer_tx(chain_id, wallet).await;
        signed.encoded_2718().into()
    }

    /// Creates a tx with blob sidecar and sign it
    pub async fn tx_with_blobs(
        chain_id: u64,
        wallet: PrivateKeySigner,
    ) -> eyre::Result<TxEnvelope> {
        let mut tx = tx(chain_id, None, 0);

        let mut builder = SidecarBuilder::<SimpleCoder>::new();
        builder.ingest(b"dummy blob");

        tx.set_blob_sidecar(builder.build()?);
        tx.set_max_fee_per_blob_gas(15e9 as u128);

        let signed = Self::sign_tx(wallet, tx).await;
        Ok(signed)
    }

    /// Signs an arbitrary [`TransactionRequest`] using the provided wallet
    pub async fn sign_tx(wallet: PrivateKeySigner, tx: TransactionRequest) -> TxEnvelope {
        let signer = EthereumWallet::from(wallet);
        <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx, &signer).await.unwrap()
    }

    /// Creates a tx with blob sidecar and sign it, returning bytes
    pub async fn tx_with_blobs_bytes(
        chain_id: u64,
        wallet: PrivateKeySigner,
    ) -> eyre::Result<Bytes> {
        let signed = Self::tx_with_blobs(chain_id, wallet).await?;

        Ok(signed.encoded_2718().into())
    }

    /// Creates and encodes an Optimism L1 block information transaction.
    pub async fn optimism_l1_block_info_tx(
        chain_id: u64,
        wallet: PrivateKeySigner,
        nonce: u64,
    ) -> Bytes {
        let l1_block_info = Bytes::from_static(&hex!("7ef9015aa044bae9d41b8380d781187b426c6fe43df5fb2fb57bd4466ef6a701e1f01e015694deaddeaddeaddeaddeaddeaddeaddeaddead000194420000000000000000000000000000000000001580808408f0d18001b90104015d8eb900000000000000000000000000000000000000000000000000000000008057650000000000000000000000000000000000000000000000000000000063d96d10000000000000000000000000000000000000000000000000000000000009f35273d89754a1e0387b89520d989d3be9c37c1f32495a88faf1ea05c61121ab0d1900000000000000000000000000000000000000000000000000000000000000010000000000000000000000002d679b567db6187c0c8323fa982cfb88b74dbcc7000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"));
        let tx = tx(chain_id, Some(l1_block_info), nonce);
        let signer = EthereumWallet::from(wallet);
        <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx, &signer)
            .await
            .unwrap()
            .encoded_2718()
            .into()
    }

    /// Validates the sidecar of a given tx envelope and returns the versioned hashes
    pub fn validate_sidecar(tx: TxEnvelope) -> Vec<B256> {
        let proof_setting = EnvKzgSettings::Default;

        match tx {
            TxEnvelope::Eip4844(signed) => match signed.tx() {
                TxEip4844Variant::TxEip4844WithSidecar(tx) => {
                    tx.validate_blob(proof_setting.get()).unwrap();
                    tx.sidecar.versioned_hashes().collect()
                }
                _ => panic!("Expected Eip4844 transaction with sidecar"),
            },
            _ => panic!("Expected Eip4844 transaction"),
        }
    }
}

/// Creates a type 2 transaction
fn tx(chain_id: u64, data: Option<Bytes>, nonce: u64) -> TransactionRequest {
    TransactionRequest {
        nonce: Some(nonce),
        value: Some(U256::from(100)),
        to: Some(TxKind::Call(Address::random())),
        gas: Some(210000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(20e9 as u128),
        chain_id: Some(chain_id),
        input: TransactionInput { input: None, data },
        ..Default::default()
    }
}

pub struct SeismicTransactionTestContext;
impl SeismicTransactionTestContext {
    /// Creates an arbitrary and signs it, returning bytes
    pub async fn sign_seismic_tx(
        wallet: &PrivateKeySigner,
        chain_id: u64,
        nonce: u64,
        to: TxKind,
        input: Bytes,
    ) -> Bytes {
        let tx = seismic_tx(&wallet, chain_id, input, nonce, to);
        let tx_signed = Self::sign_tx(&wallet, tx).await;
        tx_signed.envelope_encoded().into()
    }

    /// Creates a static transfer and signs it, returning bytes
    pub async fn deploy_tx_bytes(chain_id: u64, wallet: PrivateKeySigner, nonce: u64) -> Bytes {
        // Source code of the contract deployed:
        // pragma solidity ^0.8.0;

        // contract NoOpContract {
        //     // A function that does nothing and has no return value.
        //     function noop() external pure {
        //         // This function is intentionally left blank.
        //     }
        // }

        let contract_deploy = Bytes::from_static(&hex!("6080604052348015600e575f5ffd5b50606a80601a5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c80635dfc2e4a14602a575b5f5ffd5b60306032565b005b56fea2646970667358221220e809544020cceb1476f64dbe65da32b56bf6da2cf6da4aabbd286bf9905380c764736f6c634300081c0033"));
        let tx = seismic_tx(&wallet, chain_id, contract_deploy, nonce, TxKind::Create);
        let tx_signed = Self::sign_tx(&wallet, tx).await;
        tx_signed.envelope_encoded().into()
    }

    /// Creates a static transfer and signs it, returning bytes
    pub async fn call_seismic_tx_bytes(
        chain_id: u64,
        wallet: PrivateKeySigner,
        nonce: u64,
        address: Address,
        data: Bytes,
    ) -> Bytes {
        let selector = Bytes::from("5dfc2e4a");
        let tx_input = [selector, data].concat();

        let tx = seismic_tx(&wallet, chain_id, tx_input.into(), nonce, TxKind::Call(address));
        let tx_signed = Self::sign_tx(&wallet, tx).await;
        tx_signed.envelope_encoded().into()
    }

    /// Creates a static transfer and signs it, returning bytes
    pub async fn call_legacy_tx_bytes(
        chain_id: u64,
        wallet: PrivateKeySigner,
        nonce: u64,
        address: Address,
        data: Bytes,
    ) -> Bytes {
        let selector = Bytes::from("5dfc2e4a");
        let tx_input = [selector, data].concat();

        let tx = legacy_tx(chain_id, tx_input.into(), nonce, TxKind::Call(address));
        let tx_signed = Self::sign_tx(&wallet, tx).await;
        tx_signed.envelope_encoded().into()
    }

    /// Signs an arbitrary [`TransactionRequest`] using the provided wallet
    pub async fn sign_tx(wallet: &PrivateKeySigner, tx: Transaction) -> TransactionSigned {
        let signature = wallet.sign_hash(&tx.signature_hash()).await.unwrap();
        TransactionSigned::from_transaction_and_signature(tx, signature.into())
    }
}

/// Creates a type 2 transaction
pub fn legacy_tx(chain_id: u64, input: Bytes, nonce: u64, to: TxKind) -> Transaction {
    Transaction::Legacy(TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 20e9 as u128,
        gas_limit: 600000,
        to,
        value: U256::from(1000),
        input,
    })
}

/// Create a seismic transaction
pub fn seismic_tx(
    sk_wallet: &PrivateKeySigner,
    chain_id: u64,
    decrypted_input: Bytes,
    nonce: u64,
    to: TxKind,
) -> Transaction {
    let sk = SecretKey::from_slice(&sk_wallet.credential().to_bytes())
        .expect("32 bytes, within curve order");
    let tee_wallet = MockWallet {};

    let encrypted_input = tee_wallet.encrypt(decrypted_input.to_vec(), nonce, &sk).unwrap();

    Transaction::Seismic(TxSeismic {
        chain_id,
        nonce,
        gas_price: 20e9 as u128,
        gas_limit: 600000,
        to,
        value: U256::from(0),
        input: encrypted_input.into(),
    })
}
