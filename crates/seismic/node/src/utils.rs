//! Test utilities for Seismic E2E tests.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test utilities - panics are acceptable

/// E2E test helpers: node setup, chain advancement, payload attributes.
#[cfg(feature = "test-utils")]
pub mod e2e {
    use crate::{node::SeismicNode, purpose_keys::init_purpose_keyring};
    use alloy_primitives::{address, Address, B256};
    use alloy_rpc_types_engine::PayloadAttributes;
    use alloy_seismic_evm::PurposeKeys;
    use reth_chainspec::{make_genesis_header, ChainSpec};
    use reth_e2e_test_utils::{
        transaction::TransactionTestContext, wallet::Wallet, NodeHelperType, TmpDB,
    };
    use reth_node_api::NodeTypesWithDBAdapter;
    use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes};
    use reth_primitives_traits::SealedHeader;
    use reth_provider::providers::BlockchainProvider;
    use reth_seismic_chainspec::SEISMIC_DEV;
    use reth_seismic_keys::PurposeKeyring;
    use reth_seismic_primitives::SeismicPrimitives;
    use reth_tasks::TaskManager;
    use seismic_revm::gas_token_registry::GAS_TOKEN_REGISTRY;
    use std::sync::{Arc, Once};
    use tokio::sync::Mutex;

    /// Seismic returns times in milliseconds
    pub const SEISMIC_TIMESTAMP_MULTIPLIER: u64 = 1000;

    static INIT_KEYS: Once = Once::new();

    /// Initializes a mock purpose keyring for tests. Safe to call multiple times.
    pub fn ensure_mock_purpose_keys() {
        INIT_KEYS.call_once(|| {
            init_purpose_keyring(Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())));
        });
    }

    /// Seismic Node Helper type
    pub type SeismicTestNode =
        NodeHelperType<SeismicNode, BlockchainProvider<NodeTypesWithDBAdapter<SeismicNode, TmpDB>>>;

    /// Clone the embedded dev genesis with administrators the E2E wallet can sign for.
    ///
    /// Only the test copy's `GasTokenRegistry` and `ProtocolParams` owner words change.
    /// The registry remains empty, contract code and other storage remain untouched,
    /// and the header/hash are recomputed before node initialization. No builder or
    /// artifact downloads run during E2E setup.
    pub fn test_chain_spec() -> Arc<ChainSpec> {
        let mut spec = SEISMIC_DEV.as_ref().clone();
        let owner = Wallet::default().inner.address().into_word();
        let protocol_params = address!("0x0000000000000000000000000000506172616d73");
        for contract in [GAS_TOKEN_REGISTRY, protocol_params] {
            spec.genesis
                .alloc
                .get_mut(&contract)
                .expect("dev genesis allocates the owner-managed predeploy")
                .storage
                .get_or_insert_with(Default::default)
                .insert(B256::ZERO, owner);
        }
        spec.genesis_header =
            SealedHeader::seal_slow(make_genesis_header(&spec.genesis, &spec.hardforks));
        Arc::new(spec)
    }

    /// Creates `num_nodes` connected nodes using the E2E wallet-owned test genesis.
    pub async fn setup(
        num_nodes: usize,
    ) -> eyre::Result<(Vec<SeismicTestNode>, TaskManager, Wallet)> {
        reth_e2e_test_utils::setup_engine(
            num_nodes,
            test_chain_spec(),
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy_primitives::U256;
        use seismic_revm::gas_token_registry::TOKEN_COUNT_SLOT;

        #[test]
        fn owner_override_is_isolated_and_recomputes_the_genesis_hash() {
            let before = SEISMIC_DEV.genesis.clone();
            let original_hash = SEISMIC_DEV.genesis_header.hash();
            let spec = test_chain_spec();
            let protocol_params = address!("0x0000000000000000000000000000506172616d73");
            let expected_owner = Wallet::default().inner.address().into_word();
            let mut expected = before.clone();
            for contract in [GAS_TOKEN_REGISTRY, protocol_params] {
                expected
                    .alloc
                    .get_mut(&contract)
                    .unwrap()
                    .storage
                    .as_mut()
                    .unwrap()
                    .insert(B256::ZERO, expected_owner);
                assert_eq!(
                    spec.genesis
                        .alloc
                        .get(&contract)
                        .unwrap()
                        .storage
                        .as_ref()
                        .unwrap()
                        .get(&B256::ZERO),
                    Some(&expected_owner)
                );
            }
            assert_eq!(spec.genesis, expected);
            assert_eq!(SEISMIC_DEV.genesis, before, "shared dev template must not be mutated");
            assert_eq!(SEISMIC_DEV.genesis_header.hash(), original_hash);
            assert_ne!(spec.genesis_header.hash(), original_hash);
            assert_eq!(
                spec.genesis_header.hash(),
                make_genesis_header(&spec.genesis, &spec.hardforks).hash_slow()
            );
            let storage =
                spec.genesis.alloc.get(&GAS_TOKEN_REGISTRY).unwrap().storage.as_ref().unwrap();
            assert_eq!(
                storage.get(&B256::from(TOKEN_COUNT_SLOT.to_be_bytes::<32>())),
                Some(&B256::ZERO)
            );
            assert!(
                spec.genesis.alloc.get(&Wallet::default().inner.address()).unwrap().balance >
                    U256::ZERO,
                "the owner must already have native bootstrap funds"
            );
        }
    }
}

/// RPC test utilities: nonce helpers.
pub mod test_utils {
    use alloy_primitives::Address;
    use alloy_rpc_types::{Block, Header, Transaction, TransactionReceipt};
    use jsonrpsee::http_client::HttpClient;
    use reth_rpc_eth_api::EthApiClient;
    use seismic_alloy_rpc_types::SeismicTransactionRequest;

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
