//! Regression: real gas payment makes USDC storage private, but public balance RPCs must
//! neither read nor disclose the resulting USDC-derived balance.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types::Block;
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
use reth_seismic_txpool::usdc::{usdc_balance_storage_key, USDC_CONTRACT, USDC_DECIMAL_SCALE};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread")]
async fn private_usdc_balance_is_not_exposed_by_unsigned_balance_rpcs() -> eyre::Result<()> {
    ensure_mock_purpose_keys();
    // dev.json has balances but no code at USDC_CONTRACT. Give the predeploy
    // minimal nonempty runtime code so EIP-161 does not clear it as a touched
    // empty account when gas is charged. No storage privacy flags are injected.
    let mut spec = SEISMIC_DEV.as_ref().clone();
    spec.genesis.alloc.get_mut(&USDC_CONTRACT).unwrap().code = Some(Bytes::from_static(&[0x00]));
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
    let signer: PrivateKeySigner =
        "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e".parse()?;
    let victim = signer.address();
    let slot = usdc_balance_storage_key(&victim);

    // A legitimate victim transaction pays gas using USDC. The pinned revm's
    // confidential gas-accounting writes turn the initially public fixture private.
    node.advance_block().await?;
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
    let stored = state.storage(USDC_CONTRACT, slot)?.unwrap();
    assert!(stored.is_private(), "must demonstrate a private slot, got {stored:?}");
    assert!(stored.value > U256::ZERO);
    assert!(stored.value < U256::from(1_000_000_000u64), "gas must have been charged");

    // Unsigned balance requests expose only the fixed placeholder or actual public native
    // state, even after confidential gas accounting has written a nonzero private USDC slot.
    let compatibility: U256 =
        client.request("eth_getBalance", rpc_params![victim, "latest"]).await?;
    let native: U256 =
        client.request("eth_getBalance", rpc_params![victim, "latest", true]).await?;
    let info: serde_json::Value =
        client.request("eth_getAccountInfo", rpc_params![victim, "latest"]).await?;
    let info_balance: U256 = serde_json::from_value(info["balance"].clone())?;
    assert_eq!(compatibility, COMPATIBILITY_BALANCE);
    assert_ne!(compatibility, stored.value * USDC_DECIMAL_SCALE);
    assert_eq!(native, U256::ZERO);
    assert_eq!(info_balance, native);
    assert_eq!(info["nonce"], "0x1", "native account nonce is unchanged by the RPC policy");
    assert_eq!(info["code"], "0x");
    let legacy: Result<serde_json::Value, _> =
        client.request("eth_getAccountInfo", rpc_params![victim, "latest", true]).await;
    assert!(matches!(legacy, Err(jsonrpsee::core::ClientError::Call(err)) if err.code() == -32602));

    // Storage APIs are disabled by default, but this does not gate the above reads.
    let storage: Result<B256, _> =
        client.request("eth_getStorageAt", rpc_params![USDC_CONTRACT, slot, "latest"]).await;
    assert!(storage.unwrap_err().to_string().contains("Storage APIs are disabled"));
    println!(
        "private={}, raw_usdc={}, native={}, eth_getBalance={}, eth_getAccountInfo.balance={}",
        stored.is_private(),
        stored.value,
        native,
        compatibility,
        info_balance
    );
    Ok(())
}
