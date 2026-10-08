//! Registered Shielded gas balances must never leak through public balance RPCs.
//!
//! The token and registry are deliberately minimal storage-writer fixtures. Entries
//! and Shielded balances are initialized by native-funded post-genesis execution;
//! this is a privacy regression, not validation of the production registry artifact.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types::Block;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use reth_chainspec::make_genesis_header;
use reth_primitives_traits::SealedHeader;
use reth_provider::StateProviderFactory;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_node::{
    node::SeismicNode,
    utils::e2e::{ensure_mock_purpose_keys, seismic_payload_attributes},
};
use reth_seismic_rpc::ext::{EthApiOverrideClient, COMPATIBILITY_BALANCE};
use reth_seismic_test_utils::get_signed_seismic_tx_bytes;
use seismic_revm::gas_token_registry::{
    balance_storage_key, token_metadata_slot, TokenPrecision, GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT,
};
use std::sync::Arc;

/// Emit PUSH32(value), PUSH32(slot), and SSTORE or CSTORE.
fn storage_write(code: &mut Vec<u8>, slot: U256, value: U256, private: bool) {
    code.push(0x7f);
    code.extend_from_slice(&value.to_be_bytes::<32>());
    code.push(0x7f);
    code.extend_from_slice(&slot.to_be_bytes::<32>());
    code.push(if private { 0xb1 } else { 0x55 });
}

#[tokio::test(flavor = "multi_thread")]
async fn registered_private_balance_is_not_exposed_by_unsigned_balance_rpcs() -> eyre::Result<()> {
    ensure_mock_purpose_keys();
    let signer: PrivateKeySigner =
        "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e".parse()?;
    let bootstrap: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let victim = signer.address();
    let token = Address::with_last_byte(0xee);
    let root = (U256::from(1) << 200usize) + U256::from(3);
    let slot = balance_storage_key(victim, root);
    let initial = U256::from(1_000_000_000u64);
    let precision = TokenPrecision::new(6).unwrap();
    let mut token_code = Vec::new();
    storage_write(&mut token_code, slot, initial, true);
    token_code.push(0x00);
    let mut registry_code = Vec::new();
    let metadata = U256::from_be_slice(token.as_slice()) |
        (U256::from(1) << 160usize) | // active, Shielded mode = 0
        (U256::from(6) << 176usize);
    storage_write(&mut registry_code, token_metadata_slot(0), metadata, false);
    storage_write(&mut registry_code, token_metadata_slot(0) + U256::from(1), root, false);
    storage_write(&mut registry_code, TOKEN_COUNT_SLOT, U256::from(1), false);
    registry_code.push(0x00);

    let mut spec = SEISMIC_DEV.as_ref().clone();
    spec.genesis
        .alloc
        .insert(token, GenesisAccount { code: Some(token_code.into()), ..Default::default() });
    spec.genesis.alloc.insert(
        GAS_TOKEN_REGISTRY,
        GenesisAccount { code: Some(registry_code.into()), ..Default::default() },
    );
    spec.genesis.alloc.insert(victim, GenesisAccount::default());
    spec.genesis_header =
        SealedHeader::seal_slow(make_genesis_header(&spec.genesis, &spec.hardforks));
    let (mut nodes, _tasks, wallet) = tokio::spawn(async move {
        reth_e2e_test_utils::setup_engine::<SeismicNode>(
            1,
            Arc::new(spec),
            false,
            Default::default(),
            seismic_payload_attributes,
        )
        .await
    })
    .await??;
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url())?;

    // Both bootstrap calls pay natively. No registered token or private balance
    // exists at genesis, and no fee write converts nonzero public storage.
    for (nonce, destination) in [token, GAS_TOKEN_REGISTRY].into_iter().enumerate() {
        let tx = TxLegacy {
            chain_id: Some(wallet.chain_id),
            nonce: nonce as u64,
            gas_price: 20_000_000_000,
            gas_limit: 200_000,
            to: TxKind::Call(destination),
            ..Default::default()
        };
        let signature = bootstrap.sign_hash_sync(&tx.signature_hash())?;
        let hash = EthApiOverrideClient::<Block>::send_raw_transaction(
            &client,
            Bytes::from(tx.into_signed(signature).encoded_2718()).into(),
        )
        .await?;
        node.advance_block().await?;
        let receipt: serde_json::Value =
            client.request("eth_getTransactionReceipt", rpc_params![hash]).await?;
        assert_eq!(receipt["status"], "0x1", "bootstrap must execute successfully");
    }
    {
        let state = node.inner.provider.latest()?;
        let funded = state.storage(token, slot.to_be_bytes::<32>().into())?.unwrap();
        assert!(funded.is_private());
        assert_eq!(funded.value, initial);
    }
    let block: serde_json::Value =
        client.request("eth_getBlockByNumber", rpc_params!["latest", false]).await?;
    let recent: B256 = block["hash"].as_str().unwrap().parse()?;
    let tx = get_signed_seismic_tx_bytes(
        &signer,
        0,
        TxKind::Call(Address::with_last_byte(0xab)),
        wallet.chain_id,
        Bytes::new(),
        recent,
    )
    .await;
    let hash = EthApiOverrideClient::<Block>::send_raw_transaction(&client, tx.into()).await?;
    node.advance_block().await?;
    let receipt: serde_json::Value =
        client.request("eth_getTransactionReceipt", rpc_params![hash]).await?;
    assert_eq!(receipt["status"], "0x1");
    let state = node.inner.provider.latest()?;
    let stored = state.storage(token, slot.to_be_bytes::<32>().into())?.unwrap();
    assert!(stored.is_private());
    assert!(stored.value > U256::ZERO);
    assert!(stored.value < initial, "registered token gas must have been charged");

    let compatibility: U256 =
        client.request("eth_getBalance", rpc_params![victim, "latest"]).await?;
    let native: U256 =
        client.request("eth_getBalance", rpc_params![victim, "latest", true]).await?;
    let info: serde_json::Value =
        client.request("eth_getAccountInfo", rpc_params![victim, "latest"]).await?;
    let info_balance: U256 = serde_json::from_value(info["balance"].clone())?;
    assert_eq!(compatibility, COMPATIBILITY_BALANCE);
    assert_ne!(compatibility, precision.aggregate(stored.value));
    assert_eq!(native, U256::ZERO);
    assert_eq!(info_balance, native);
    assert_eq!(info["nonce"], "0x1");
    assert_eq!(info["code"], "0x");
    let legacy: Result<serde_json::Value, _> =
        client.request("eth_getAccountInfo", rpc_params![victim, "latest", true]).await;
    assert!(matches!(legacy, Err(jsonrpsee::core::ClientError::Call(err)) if err.code() == -32602));
    let storage: Result<B256, _> = client
        .request(
            "eth_getStorageAt",
            rpc_params![token, B256::from(slot.to_be_bytes::<32>()), "latest"],
        )
        .await;
    assert!(storage.unwrap_err().to_string().contains("Storage APIs are disabled"));
    Ok(())
}
