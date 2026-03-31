//! Ops signature-auth server tests

use crate::utils::test_address;
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, B256, Bytes, FlaggedStorage, TxKind, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_rpc::OpsApi;
use reth_rpc_api::OpsApiServer;
use reth_rpc_builder::body_auth::{BodyAuthRpcModule, BodyAuthServerConfig, BodyAuthServerHandle};
use reth_rpc_layer::{
    eip712_signing_hash, SignatureAuthConfig, Whitelist, SIGNED_TX_HEADER,
    WHITELIST_TX_SENTINEL,
};
use reth_tasks::TokioTaskExecutor;
use std::sync::Arc;

sol! {
    interface OpsWhitelistTxAuth {
        function whitelistKey(address target, uint64 expiresAt) external;
    }
}

/// Fixed contract address, slot, and chain ID for tests.
const CONTRACT_ADDRESS: Address = Address::ZERO;
const STORAGE_SLOT: B256 = B256::ZERO;
const TEST_CHAIN_ID: u64 = 1;

/// Create a mock provider with a specific admin address stored at the contract slot.
fn mock_provider_with_admin(admin_address: Address) -> Arc<MockEthProvider> {
    let provider = MockEthProvider::default();
    let mut value = [0u8; 32];
    value[12..].copy_from_slice(admin_address.as_slice());
    let storage_value = FlaggedStorage::new_from_value(U256::from_be_bytes(value));
    let account =
        ExtendedAccount::new(0, U256::ZERO).extend_storage([(STORAGE_SLOT, storage_value)]);
    provider.add_account(CONTRACT_ADDRESS, account);
    Arc::new(provider)
}

/// Launch an ops server with the given admin address.
async fn launch_ops_with_admin(
    admin_address: Address,
) -> (BodyAuthServerHandle, Whitelist) {
    let provider = mock_provider_with_admin(admin_address);
    let whitelist = Whitelist::new();
    let nonces = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    let mut auth_config = SignatureAuthConfig::new(
        provider.clone(),
        CONTRACT_ADDRESS,
        STORAGE_SLOT,
        whitelist.clone(),
        TEST_CHAIN_ID,
    );
    auth_config.nonces = nonces.clone();

    let ops_api = OpsApi::new(
        provider,
        Box::new(TokioTaskExecutor::default()),
        whitelist.clone(),
        nonces,
    );

    let mut module = BodyAuthRpcModule::empty();
    module.merge_methods(ops_api.into_rpc()).unwrap();

    let server_config = BodyAuthServerConfig::builder(auth_config)
        .socket_addr(test_address())
        .build();

    let handle = server_config.start(module).await.unwrap();
    (handle, whitelist)
}

fn get_storage_request(address: Address, index: B256, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_getStorageAt",
        "params": [format!("{address:?}"), format!("{index:?}"), "latest"],
        "id": id
    })
    .to_string()
}

fn whitelist_key_request(address: Address, expires_at: u64, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_whitelistKey",
        "params": [format!("{address:?}"), expires_at],
        "id": id
    })
    .to_string()
}

fn revoke_key_request(address: Address, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_revokeKey",
        "params": [format!("{address:?}")],
        "id": id
    })
    .to_string()
}

fn get_nonce_request(address: Address, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_getNonce",
        "params": [format!("{address:?}")],
        "id": id
    })
    .to_string()
}

async fn send_signed_request(
    url: &str,
    body: &str,
    signer: &PrivateKeySigner,
    nonce: Option<&str>,
) -> reqwest::Response {
    let signing_nonce = nonce.unwrap_or("");
    let hash = eip712_signing_hash(body.as_bytes(), signing_nonce, TEST_CHAIN_ID);

    let signature = signer.sign_hash(&hash).await.unwrap();
    let sig_hex = alloy_primitives::hex::encode(signature.as_bytes());

    let mut req = reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Signature", &sig_hex);
    if let Some(nonce) = nonce {
        req = req.header("X-Nonce", nonce);
    }
    req.body(body.to_string()).send().await.unwrap()
}

async fn send_whitelist_request(
    url: &str,
    body: &str,
    signer: &PrivateKeySigner,
    target: Address,
    expires_at: u64,
) -> reqwest::Response {
    let signed_tx = signed_whitelist_tx(signer, target, expires_at);

    reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .header(SIGNED_TX_HEADER, signed_tx)
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

fn signed_whitelist_tx(signer: &PrivateKeySigner, target: Address, expires_at: u64) -> String {
    let calldata = Bytes::from(OpsWhitelistTxAuth::whitelistKeyCall { target, expiresAt: expires_at }.abi_encode());
    let mut tx = TxLegacy {
        chain_id: Some(TEST_CHAIN_ID),
        nonce: 0,
        gas_limit: 21_000,
        gas_price: 0,
        to: TxKind::Call(WHITELIST_TX_SENTINEL),
        value: U256::ZERO,
        input: calldata,
    };

    let mut signer = signer.clone();
    signer.set_chain_id(Some(TEST_CHAIN_ID));
    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    let envelope = TxEnvelope::Legacy(tx.into_signed(signature));
    format!("0x{}", alloy_primitives::hex::encode(envelope.encoded_2718()))
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_request_without_signature_is_rejected() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;

    let body = get_storage_request(Address::ZERO, B256::ZERO, 1);
    let resp = reqwest::Client::new()
        .post(&handle.http_url())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_get_storage_at_requires_whitelisted_key() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin key should NOT be able to call getStorageAt
    let body = get_storage_request(Address::ZERO, B256::ZERO, 1);
    let resp = send_signed_request(&url, &body, &admin, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Random key should NOT be able to call getStorageAt
    let random = PrivateKeySigner::random();
    let resp = send_signed_request(&url, &body, &random, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_whitelist_key_requires_admin() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    let target = PrivateKeySigner::random();

    // Non-admin should NOT be able to whitelist
    let expires_at = current_unix_timestamp() + 3600;
    let body = whitelist_key_request(target.address(), expires_at, 1);
    let resp = send_whitelist_request(
        &url,
        &body,
        &target,
        target.address(),
        expires_at,
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Admin should be able to whitelist
    let resp = send_whitelist_request(&url, &body, &admin, target.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_whitelisted_key_can_read_storage() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Reader can't read yet
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 1);
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Admin whitelists the reader (1 hour TTL)
    let expires_at = current_unix_timestamp() + 3600;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 2);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Now reader can read
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json["result"].is_string());

    // Reusing the same nonce should fail
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // The next nonce should succeed
    let resp = send_signed_request(&url, &read_body, &reader, Some("1")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_whitelist_expires() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin whitelists reader until one second from now.
    let expires_at = current_unix_timestamp() + 1;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 1);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Reader can read immediately
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 2);
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Reader can no longer read
    let resp = send_signed_request(&url, &read_body, &reader, Some("1")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_whitelist_key_rejects_expired_timestamp() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let target = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    let expires_at = current_unix_timestamp() - 1;
    let body = whitelist_key_request(target.address(), expires_at, 1);
    let resp =
        send_whitelist_request(&url, &body, &admin, target.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body_text = resp.text().await.unwrap();
    assert_eq!(body_text, "Expiry timestamp must be in the future");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_revoke_key() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin whitelists reader
    let expires_at = current_unix_timestamp() + 3600;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 1);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Reader can read
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 2);
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Admin revokes reader
    let revoke_body = revoke_key_request(reader.address(), 3);
    let resp = send_signed_request(&url, &revoke_body, &admin, None).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], true);

    // Reader can no longer read
    let resp = send_signed_request(&url, &read_body, &reader, Some("1")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Revoking again returns false (not found)
    let resp = send_signed_request(&url, &revoke_body, &admin, None).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_revoke_key_requires_admin() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Non-admin cannot revoke
    let revoke_body = revoke_key_request(reader.address(), 1);
    let resp = send_signed_request(&url, &revoke_body, &reader, None).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_expired_whitelist_cannot_read_storage() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin whitelists reader until one second from now.
    let expires_at = current_unix_timestamp() + 1;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 1);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Wait for the whitelist entry to expire.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Reader should be rejected — whitelist expired
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 2);
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Re-whitelist with a longer absolute expiry.
    let expires_at = current_unix_timestamp() + 3600;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 3);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Reader can read again
    let resp = send_signed_request(&url, &read_body, &reader, Some("0")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_get_nonce_for_whitelisted_key() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    let expires_at = current_unix_timestamp() + 3600;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 1);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let nonce_body = get_nonce_request(reader.address(), 2);
    let resp = send_signed_request(&url, &nonce_body, &reader, None).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_get_nonce_rejects_other_address() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let other = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    let expires_at = current_unix_timestamp() + 3600;
    let wl_body = whitelist_key_request(reader.address(), expires_at, 1);
    let resp = send_whitelist_request(&url, &wl_body, &admin, reader.address(), expires_at).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let nonce_body = get_nonce_request(other.address(), 2);
    let resp = send_signed_request(&url, &nonce_body, &reader, None).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
