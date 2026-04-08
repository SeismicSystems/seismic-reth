//! Test utilities for Seismic E2E tests.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test utilities - panics are acceptable

/// E2E test helpers: node setup, chain advancement, payload attributes.
#[cfg(feature = "test-utils")]
pub mod e2e {
    use crate::{node::SeismicNode, purpose_keys::init_purpose_keys};
    use alloy_primitives::{Address, B256};
    use alloy_rpc_types_engine::PayloadAttributes;
    use reth_e2e_test_utils::{
        transaction::TransactionTestContext, wallet::Wallet, NodeHelperType, TmpDB,
    };
    use reth_node_api::NodeTypesWithDBAdapter;
    use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes};
    use reth_provider::providers::BlockchainProvider;
    use reth_seismic_chainspec::SEISMIC_DEV;
    use reth_seismic_primitives::SeismicPrimitives;
    use reth_tasks::TaskManager;
    use seismic_enclave::{
        get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
        get_unsecure_sample_secp256k1_sk, GetPurposeKeysResponse,
    };
    use std::sync::{Arc, Once};
    use tokio::sync::Mutex;

    /// Seismic returns times in milliseconds
    pub const SEISMIC_TIMESTAMP_MULTIPLIER: u64 = 1000;

    static INIT_KEYS: Once = Once::new();

    /// Initializes mock purpose keys for tests. Safe to call multiple times.
    pub fn ensure_mock_purpose_keys() {
        INIT_KEYS.call_once(|| {
            init_purpose_keys(GetPurposeKeysResponse {
                tx_io_sk: get_unsecure_sample_secp256k1_sk(),
                tx_io_pk: get_unsecure_sample_secp256k1_pk(),
                snapshot_key_bytes: [0u8; 32],
                rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
            });
        });
    }

    /// Seismic Node Helper type
    pub type SeismicTestNode =
        NodeHelperType<SeismicNode, BlockchainProvider<NodeTypesWithDBAdapter<SeismicNode, TmpDB>>>;

    /// Creates the initial setup with `num_nodes` of the seismic node config, started and
    /// connected.
    pub async fn setup(
        num_nodes: usize,
    ) -> eyre::Result<(Vec<SeismicTestNode>, TaskManager, Wallet)> {
        reth_e2e_test_utils::setup_engine(
            num_nodes,
            SEISMIC_DEV.clone(),
            false,
            Default::default(),
            seismic_payload_attributes,
        )
        .await
    }

    /// Advance the chain with sequential payloads returning them in the end.
    pub async fn advance_chain(
        length: usize,
        node: &mut SeismicTestNode,
        wallet: Arc<Mutex<Wallet>>,
    ) -> eyre::Result<Vec<EthBuiltPayload<SeismicPrimitives>>> {
        node.advance(length as u64, |_| {
            let wallet = wallet.clone();
            Box::pin(async move {
                let mut wallet = wallet.lock().await;
                let nonce = wallet.inner_nonce;
                wallet.inner_nonce += 1;
                let tx = alloy_rpc_types_eth::TransactionRequest {
                    nonce: Some(nonce),
                    value: Some(alloy_primitives::U256::from(100)),
                    to: Some(alloy_primitives::TxKind::Call(Address::random())),
                    gas: Some(21000),
                    max_fee_per_gas: Some(20e9 as u128),
                    max_priority_fee_per_gas: Some(20e9 as u128),
                    chain_id: Some(wallet.chain_id),
                    ..Default::default()
                };
                let signed = TransactionTestContext::sign_tx(wallet.inner.clone(), tx).await;
                alloy_eips::eip2718::Encodable2718::encoded_2718(&signed).into()
            })
        })
        .await
    }

    /// Helper function to create a new eth payload attributes for seismic
    pub fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
        let attributes = PayloadAttributes {
            timestamp: timestamp * SEISMIC_TIMESTAMP_MULTIPLIER,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: Address::ZERO,
            withdrawals: Some(vec![]),
            parent_beacon_block_root: Some(B256::ZERO),
        };
        EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
    }
}

/// RPC test utilities: nonce helpers, re-exported test helpers.
pub mod test_utils {
    use alloy_primitives::Address;
    use alloy_rpc_types::{Block, Header, Transaction, TransactionReceipt};
    use jsonrpsee::http_client::HttpClient;
    use reth_rpc_eth_api::EthApiClient;
    use seismic_alloy_rpc_types::SeismicTransactionRequest;

    pub use reth_seismic_primitives::test_utils::{
        client_decrypt, client_encrypt, get_ciphertext, get_client_io_sk, get_encryption_nonce,
        get_network_public_key, get_plaintext, get_seismic_elements, get_seismic_metadata,
        get_seismic_tx, get_signed_seismic_tx, get_signed_seismic_tx_bytes,
        get_signed_seismic_tx_encoding, get_signed_seismic_tx_typed_data, get_signing_private_key,
        get_unsigned_seismic_tx_request, get_unsigned_seismic_tx_typed_data, get_wrong_private_key,
        sign_seismic_tx, sign_tx,
    };

    /// Get the nonce from the client
    pub async fn get_nonce(client: &HttpClient, address: Address) -> u64 {
        let nonce = EthApiClient::<
            SeismicTransactionRequest,
            Transaction,
            Block,
            TransactionReceipt,
            Header,
        >::transaction_count(client, address, None)
        .await
        .unwrap();
        nonce.wrapping_to::<u64>()
    }
}
