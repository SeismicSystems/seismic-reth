//! E2E test helpers: node setup, chain advancement, payload attributes.

use alloy_primitives::{address, Address, B256, U256};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_seismic_evm::PurposeKeys;
use reth_chainspec::{make_genesis_header, ChainSpec};
use reth_e2e_test_utils::{
    transaction::TransactionTestContext, wallet::Wallet, NodeHelperType, TmpDB,
};
use reth_node_api::NodeTypesWithDBAdapter;
use reth_primitives_traits::SealedHeader;
use reth_provider::providers::BlockchainProvider;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_engine_primitives::{
    SeismicBuiltPayload, SeismicPayloadAttributes, SeismicPayloadBuilderAttributes,
};
use reth_seismic_keys::PurposeKeyring;
use reth_seismic_node::{node::SeismicNode, purpose_keys::init_purpose_keyring};
use reth_tasks::TaskManager;
use seismic_revm::gas_token_registry::GAS_TOKEN_REGISTRY;
use std::sync::{Arc, Once};
use tokio::sync::Mutex;

static INIT_KEYS: Once = Once::new();

// One million native tokens, allocated only in the isolated E2E genesis.
pub(crate) const TEST_WALLET_BALANCE: u128 = 1_000_000_000_000_000_000_000_000;

/// Initializes a mock purpose keyring for tests. Safe to call multiple times.
pub(crate) fn ensure_mock_purpose_keys() {
    INIT_KEYS.call_once(|| {
        init_purpose_keyring(Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())));
    });
}

/// Seismic Node Helper type
pub(crate) type SeismicTestNode =
    NodeHelperType<SeismicNode, BlockchainProvider<NodeTypesWithDBAdapter<SeismicNode, TmpDB>>>;

/// Clone the embedded dev genesis with administrators the E2E wallet can sign for.
///
/// The test copy funds the E2E wallet and replaces the `GasTokenRegistry` and
/// `ProtocolParams` owner words. The registry remains empty, contract code and
/// other storage remain untouched, and the header/hash are recomputed before
/// node initialization. No builder or artifact downloads run during E2E setup.
pub(crate) fn test_chain_spec() -> Arc<ChainSpec> {
    let mut spec = (**SEISMIC_DEV).clone();
    let owner_address = Wallet::default().inner.address();
    spec.genesis.alloc.entry(owner_address).or_default().balance = U256::from(TEST_WALLET_BALANCE);
    let owner = owner_address.into_word();
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
pub(crate) async fn setup(
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
pub(crate) async fn advance_chain(
    length: usize,
    node: &mut SeismicTestNode,
    wallet: Arc<Mutex<Wallet>>,
) -> eyre::Result<Vec<SeismicBuiltPayload>> {
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

/// Helper function to create new payload builder attributes for Seismic from a Unix
/// seconds timestamp (zero sub-second component).
pub(crate) fn seismic_payload_attributes(timestamp: u64) -> SeismicPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    SeismicPayloadBuilderAttributes::new(B256::ZERO, SeismicPayloadAttributes::new(attributes, 0))
        .expect("zero millis part is in range")
}
