//! Wire-level coverage for public balance RPCs. Internal USDC gas accounting stays separate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::integration::setup_test_node;
use alloy_primitives::{address, Address, B256, U256};
use alloy_rpc_types_eth::AccountInfo;
use jsonrpsee::{core::client::ClientT, rpc_params};
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::helpers::LoadPendingBlock;
use reth_seismic_chainspec::SEISMIC_DEV;
use reth_seismic_rpc::ext::COMPATIBILITY_BALANCE;
use serde_json::{json, Value};
use std::time::Duration;

async fn request(
    client: &reqwest::Client,
    url: reqwest::Url,
    method: &str,
    params: Value,
) -> eyre::Result<Value> {
    Ok(client
        .post(url)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[tokio::test(flavor = "multi_thread")]
async fn balance_modes_and_account_info_match_native_state() -> eyre::Result<()> {
    let (node, client, _chain_id, wallet, _tasks) = setup_test_node().await?;
    let http = reqwest::Client::new();
    let state = node.inner.provider.latest()?;
    let contract = *SEISMIC_DEV
        .genesis
        .alloc
        .iter()
        .find(|(_, account)| account.code.as_ref().is_some_and(|code| !code.is_empty()))
        .expect("dev genesis includes a contract")
        .0;

    // Empty, native-funded, USDC-funded, and contract accounts all get exactly the same
    // placeholder, while native/account-info reads must match the real provider state.
    for addr in [
        Address::with_last_byte(0xab),
        wallet.inner.address(),
        address!("976ea74026e726554db657fa54763abd0c3a0aa9"),
        contract,
    ] {
        let account = state.basic_account(&addr)?.unwrap_or_default();
        let code = state.account_code(&addr)?.map(|code| code.original_bytes()).unwrap_or_default();
        for params in [
            json!([addr]),
            json!([addr, "latest"]),
            json!([addr, null]),
            json!([addr, "latest", null]),
            json!([addr, "latest", false]),
            json!({"address": addr}),
            json!({"address": addr, "blockNumber": "latest", "native": false}),
            json!({"address": addr, "block_number": null, "native": null}),
        ] {
            let response = request(&http, node.rpc_url(), "eth_getBalance", params).await?;
            assert_eq!(response.get("error"), None, "{response}");
            assert_eq!(
                serde_json::from_value::<U256>(response["result"].clone())?,
                COMPATIBILITY_BALANCE
            );
            // Also pin the exact approved wire quantity, independently of the Rust constant.
            assert_eq!(
                response["result"],
                "0x9612084f0316e0ebd5182f398e5195a51b5ca47667d4c9b26c9b26c9b26c9b2"
            );
        }
        for params in [
            json!([addr, "latest", true]),
            json!([addr, null, true]),
            json!({"address": addr, "native": true}),
            json!({"address": addr, "blockNumber": "latest", "native": true}),
            json!({"address": addr, "block_number": "latest", "native": true}),
        ] {
            let response = request(&http, node.rpc_url(), "eth_getBalance", params).await?;
            assert_eq!(response.get("error"), None, "{response}");
            assert_eq!(
                serde_json::from_value::<U256>(response["result"].clone())?,
                account.balance
            );
        }
        for params in [json!([addr, "latest"]), json!({"address": addr, "block": "latest"})] {
            let response = request(&http, node.rpc_url(), "eth_getAccountInfo", params).await?;
            assert_eq!(response.get("error"), None, "{response}");
            let info: AccountInfo = serde_json::from_value(response["result"].clone())?;
            assert_eq!(info.balance, account.balance);
            assert_eq!(info.nonce, account.nonce);
            assert_eq!(info.code, code);
        }
        let native: U256 = client.request("eth_getBalance", rpc_params![addr, "0x0", true]).await?;
        assert_eq!(native, account.balance, "explicit genesis selector");
    }
    Ok(())
}

/// Historical selection must be tested after state changes; querying genesis while it is
/// still latest would also pass if the handler accidentally discarded the block argument.
#[tokio::test(flavor = "multi_thread")]
async fn balance_block_selectors_after_native_balance_changes() -> eyre::Result<()> {
    let (mut node, client, chain_id, wallet, _tasks) = setup_test_node().await?;
    let http = reqwest::Client::new();
    let addr = wallet.inner.address();
    let before = node.inner.provider.latest()?.account_balance(&addr)?.unwrap_or_default();
    let genesis: Value =
        client.request("eth_getBlockByNumber", rpc_params!["latest", false]).await?;
    assert_eq!(genesis["number"], "0x0");

    let tx = TransactionTestContext::transfer_tx_bytes(chain_id, wallet.inner.clone()).await;
    let tx_hash: B256 = client.request("eth_sendRawTransaction", rpc_params![tx]).await?;
    node.advance_block().await?;
    let receipt: Value = client.request("eth_getTransactionReceipt", rpc_params![tx_hash]).await?;
    assert_eq!(receipt["status"], "0x1");
    let after = node.inner.provider.latest()?.account_balance(&addr)?.unwrap_or_default();
    assert!(after < before, "the fixture must have distinct historical and latest balances");
    let latest: Value =
        client.request("eth_getBlockByNumber", rpc_params!["latest", false]).await?;
    assert_ne!(latest["hash"], genesis["hash"]);

    for (block, expected_native) in [
        (genesis["number"].clone(), before),
        (json!({"blockNumber": genesis["number"]}), before),
        (json!({"blockHash": genesis["hash"]}), before),
        (json!({"blockHash": genesis["hash"], "requireCanonical": true}), before),
        (json!("earliest"), before),
        (latest["number"].clone(), after),
        (json!({"blockHash": latest["hash"]}), after),
        (json!("latest"), after),
        (json!("pending"), after),
        (Value::Null, after),
    ] {
        for params in [
            json!([addr, block, true]),
            json!({"address": addr, "blockNumber": block, "native": true}),
            json!({"address": addr, "block_number": block, "native": true}),
        ] {
            let response = request(&http, node.rpc_url(), "eth_getBalance", params.clone()).await?;
            assert_eq!(response.get("error"), None, "{params}: {response}");
            assert_eq!(
                serde_json::from_value::<U256>(response["result"].clone())?,
                expected_native,
                "{params}"
            );
        }
        // Actually omit native; serializing Option::<bool>::None would send a third null.
        for params in [
            json!([addr, block]),
            json!({"address": addr, "blockNumber": block}),
            json!({"address": addr, "block_number": block}),
        ] {
            let response = request(&http, node.rpc_url(), "eth_getBalance", params.clone()).await?;
            assert_eq!(response.get("error"), None, "{params}: {response}");
            assert_eq!(
                serde_json::from_value::<U256>(response["result"].clone())?,
                COMPATIBILITY_BALANCE,
                "{params}"
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn balance_wire_rejects_legacy_unknown_and_extra_parameters() -> eyre::Result<()> {
    let (node, _client, _chain_id, wallet, _tasks) = setup_test_node().await?;
    let http = reqwest::Client::new();
    let addr = wallet.inner.address();
    for params in [
        json!([]),
        json!({}),
        json!([null, "latest"]),
        json!(["0x1234", "latest"]),
        json!([addr, "not-a-block"]),
        json!([addr, {"blockHash": "0x12"}]),
        json!([addr, false]),
        json!([addr, "latest", 1]),
        json!([addr, "latest", "true"]),
        json!([addr, "latest", {"native": true}]),
        json!([addr, "latest", false, null]),
        json!([addr, "latest", null, null, true]),
        json!([addr, "latest", true, false]),
        json!({"address": addr, "includeGasToken": true}),
        json!({"address": addr, "includeGasToken": false}),
        json!({"address": addr, "include_gas_token": null}),
        json!({"address": addr, "native": true, "includeGasToken": true}),
        json!({"address": addr, "native": "true"}),
        json!({"address": addr, "unknown": null}),
        json!({"address": addr, "blockNumber": "latest", "block_number": "pending"}),
    ] {
        let response = request(&http, node.rpc_url(), "eth_getBalance", params.clone()).await?;
        assert_eq!(response["error"]["code"], -32602, "{params}: {response}");
    }
    for params in [
        json!([]),
        json!([addr]),
        json!([addr, null]),
        json!(["0x1234", "latest"]),
        json!([addr, "not-a-block"]),
        json!([addr, "latest", null]),
        json!([addr, "latest", null, true]),
        json!([addr, "latest", false]),
        json!([addr, "latest", true]),
        json!([addr, "latest", {}]),
        json!({"address": addr}),
        json!({"address": addr, "block": "latest", "native": null}),
        json!({"address": addr, "block": "latest", "includeGasToken": true}),
        json!({"address": addr, "block": "latest", "include_gas_token": false}),
        json!({"address": addr, "block": "latest", "unknown": null}),
    ] {
        let response = request(&http, node.rpc_url(), "eth_getAccountInfo", params.clone()).await?;
        assert_eq!(response["error"]["code"], -32602, "{params}: {response}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn constant_balance_does_not_resolve_nonexistent_blocks() -> eyre::Result<()> {
    let (node, _client, _chain_id, wallet, _tasks) = setup_test_node().await?;
    let http = reqwest::Client::new();
    let addr = wallet.inner.address();
    for block in [
        json!("0xffffffffffffffff"),
        json!({"blockHash": B256::repeat_byte(0xff)}),
        json!({"blockHash": B256::repeat_byte(0xff), "requireCanonical": true}),
    ] {
        for params in [
            json!([addr, block]),
            json!([addr, block, null]),
            json!([addr, block, false]),
            json!({"address": addr, "blockNumber": block}),
        ] {
            let response = request(&http, node.rpc_url(), "eth_getBalance", params).await?;
            assert_eq!(response.get("error"), None, "{response}");
            assert_eq!(
                serde_json::from_value::<U256>(response["result"].clone())?,
                COMPATIBILITY_BALANCE
            );
        }
        for (method, params) in [
            ("eth_getBalance", json!([addr, block, true])),
            ("eth_getAccountInfo", json!([addr, block])),
        ] {
            let response = request(&http, node.rpc_url(), method, params).await?;
            // HeaderNotFound is rendered as "block not found" on the wire. Provider errors
            // need not preserve requireCanonical in their display of an unknown hash.
            assert_eq!(response["error"]["code"], -32001, "{response}");
            assert!(
                response["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with("block not found")),
                "{response}"
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn constant_balance_does_not_construct_pending_blocks() -> eyre::Result<()> {
    let (node, client, _chain_id, wallet, _tasks) = setup_test_node().await?;
    let eth_api = node.inner.add_ons_handle.rpc_registry.eth_api();
    assert!(!eth_api.pending_block_kind().is_none());
    // A state-resolving pending read must take this lock. Constant replies must not need it.
    let pending = eth_api.pending_block().lock().await;
    assert!(pending.is_none());
    for params in [
        rpc_params![wallet.inner.address(), "pending"],
        rpc_params![wallet.inner.address(), "pending", Option::<bool>::None],
        rpc_params![wallet.inner.address(), "pending", false],
    ] {
        let balance: U256 =
            tokio::time::timeout(Duration::from_secs(2), client.request("eth_getBalance", params))
                .await??;
        assert_eq!(balance, COMPATIBILITY_BALANCE);
    }
    assert!(pending.is_none(), "constant replies must not populate the pending cache");
    // Positive control: the native path does resolve pending state and blocks on the lock.
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        client.request::<U256, _>(
            "eth_getBalance",
            rpc_params![wallet.inner.address(), "pending", true]
        ),
    )
    .await
    .is_err());
    drop(pending);
    let native: U256 = tokio::time::timeout(
        Duration::from_secs(5),
        client.request("eth_getBalance", rpc_params![wallet.inner.address(), "pending", true]),
    )
    .await??;
    assert!(native > U256::ZERO);
    Ok(())
}
