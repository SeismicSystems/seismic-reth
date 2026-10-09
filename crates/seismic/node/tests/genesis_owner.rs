//! Test-only owner overrides must be installed before genesis and usable with real signatures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address, Bytes, TxKind, B256};
use alloy_rpc_types::Block;
use alloy_signer::SignerSync;
use alloy_sol_types::{sol, SolCall};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_provider::StateProviderFactory;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_node::utils::e2e::{ensure_mock_purpose_keys, setup, test_chain_spec};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use seismic_revm::gas_token_registry::{GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT};

sol! {
    function transferOwnership(address newOwner);
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_wallet_can_administer_the_registry_from_genesis() -> eyre::Result<()> {
    ensure_mock_purpose_keys();
    let protocol_params = address!("0x0000000000000000000000000000506172616d73");
    let original_owner = *SEISMIC_DEV
        .genesis
        .alloc
        .get(&GAS_TOKEN_REGISTRY)
        .unwrap()
        .storage
        .as_ref()
        .unwrap()
        .get(&B256::ZERO)
        .unwrap();
    let (mut nodes, _tasks, wallet) = tokio::spawn(setup(1)).await??;
    let mut node = nodes.pop().unwrap();
    let owner = wallet.inner.address().into_word();
    assert_ne!(owner, original_owner);
    assert_eq!(node.block_hash(0), test_chain_spec().genesis_header.hash());
    assert_ne!(node.block_hash(0), SEISMIC_DEV.genesis_header.hash());
    {
        let state = node.inner.provider.latest()?;
        for contract in [GAS_TOKEN_REGISTRY, protocol_params] {
            let stored = state.storage(contract, B256::ZERO)?.unwrap();
            assert_eq!(stored.value.to_be_bytes::<32>(), owner.0);
            assert!(!stored.is_private(), "genesis configuration must be public");
        }
        let count =
            state.storage(GAS_TOKEN_REGISTRY, B256::from(TOKEN_COUNT_SLOT.to_be_bytes::<32>()))?;
        assert!(count.is_none_or(|stored| stored.value.is_zero() && !stored.is_private()));
    }

    // Exercise an owner-only method through a signed native-funded transaction.
    // There is no impersonation, builder invocation, or post-startup state override.
    let next_owner = Address::with_last_byte(0xee);
    let tx = TxLegacy {
        chain_id: Some(wallet.chain_id),
        nonce: 0,
        gas_price: 20_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(GAS_TOKEN_REGISTRY),
        input: transferOwnershipCall { newOwner: next_owner }.abi_encode().into(),
        ..Default::default()
    };
    let signature = wallet.inner.sign_hash_sync(&tx.signature_hash())?;
    let client = HttpClientBuilder::default().build(node.rpc_url())?;
    let hash = EthApiOverrideClient::<Block>::send_raw_transaction(
        &client,
        Bytes::from(tx.into_signed(signature).encoded_2718()).into(),
    )
    .await?;
    node.advance_block().await?;
    let receipt: serde_json::Value =
        client.request("eth_getTransactionReceipt", rpc_params![hash]).await?;
    assert_eq!(
        receipt["status"], "0x1",
        "the E2E private key must authorize registry administration"
    );
    let state = node.inner.provider.latest()?;
    let stored = state.storage(GAS_TOKEN_REGISTRY, B256::ZERO)?.unwrap();
    assert_eq!(stored.value.to_be_bytes::<32>(), next_owner.into_word().0);
    assert!(!stored.is_private());
    assert_eq!(
        state.storage(protocol_params, B256::ZERO)?.unwrap().value.to_be_bytes::<32>(),
        owner.0,
        "the predeploys' ownership is independent after genesis"
    );
    assert_eq!(
        *SEISMIC_DEV
            .genesis
            .alloc
            .get(&GAS_TOKEN_REGISTRY)
            .unwrap()
            .storage
            .as_ref()
            .unwrap()
            .get(&B256::ZERO)
            .unwrap(),
        original_owner,
        "test startup and administration must not mutate the committed template"
    );
    Ok(())
}
