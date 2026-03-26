//! Ops signature-auth server tests

use crate::utils::test_address;
use alloy_primitives::{keccak256, Address, B256, FlaggedStorage, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_rpc::OpsApi;
use reth_rpc_api::OpsApiServer;
use reth_rpc_builder::body_auth::{BodyAuthRpcModule, BodyAuthServerConfig, BodyAuthServerHandle};
use reth_rpc_layer::{SignatureAuthConfig, Whitelist};
use reth_tasks::TokioTaskExecutor;
use std::sync::Arc;

/// Fixed contract address and slot for tests.
const CONTRACT_ADDRESS: Address = Address::ZERO;
const STORAGE_SLOT: B256 = B256::ZERO;

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
    let auth_config = SignatureAuthConfig::new(
        provider.clone(),
        CONTRACT_ADDRESS,
        STORAGE_SLOT,
        whitelist.clone(),
    );

    let ops_api = OpsApi::new(
        provider,
        Box::new(TokioTaskExecutor::default()),
        whitelist.clone(),
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

fn whitelist_key_request(address: Address, ttl_seconds: u64, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_whitelistKey",
        "params": [format!("{address:?}"), ttl_seconds],
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

async fn send_signed_request(
    url: &str,
    body: &str,
    signer: &PrivateKeySigner,
    nonce: &str,
) -> reqwest::Response {
    let mut message = Vec::with_capacity(body.len() + nonce.len());
    message.extend_from_slice(body.as_bytes());
    message.extend_from_slice(nonce.as_bytes());
    let hash = keccak256(&message);

    let signature = signer.sign_hash(&hash).await.unwrap();
    let sig_hex = alloy_primitives::hex::encode(signature.as_bytes());

    reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Signature", &sig_hex)
        .header("X-Nonce", nonce)
        .body(body.to_string())
        .send()
        .await
        .unwrap()
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
    let resp = send_signed_request(&url, &body, &admin, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Random key should NOT be able to call getStorageAt
    let random = PrivateKeySigner::random();
    let resp = send_signed_request(&url, &body, &random, "nonce2").await;
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
    let body = whitelist_key_request(target.address(), 3600, 1);
    let resp = send_signed_request(&url, &body, &target, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Admin should be able to whitelist
    let resp = send_signed_request(&url, &body, &admin, "nonce2").await;
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
    let resp = send_signed_request(&url, &read_body, &reader, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Admin whitelists the reader (1 hour TTL)
    let wl_body = whitelist_key_request(reader.address(), 3600, 2);
    let resp = send_signed_request(&url, &wl_body, &admin, "nonce2").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Now reader can read
    let resp = send_signed_request(&url, &read_body, &reader, "nonce3").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json["result"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_whitelist_expires() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin whitelists reader with 1 second TTL
    let wl_body = whitelist_key_request(reader.address(), 1, 1);
    let resp = send_signed_request(&url, &wl_body, &admin, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Reader can read immediately
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 2);
    let resp = send_signed_request(&url, &read_body, &reader, "nonce2").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Reader can no longer read
    let resp = send_signed_request(&url, &read_body, &reader, "nonce3").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_revoke_key() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin whitelists reader
    let wl_body = whitelist_key_request(reader.address(), 3600, 1);
    let resp = send_signed_request(&url, &wl_body, &admin, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Reader can read
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 2);
    let resp = send_signed_request(&url, &read_body, &reader, "nonce2").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Admin revokes reader
    let revoke_body = revoke_key_request(reader.address(), 3);
    let resp = send_signed_request(&url, &revoke_body, &admin, "nonce3").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], true);

    // Reader can no longer read
    let resp = send_signed_request(&url, &read_body, &reader, "nonce4").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Revoking again returns false (not found)
    let resp = send_signed_request(&url, &revoke_body, &admin, "nonce5").await;
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
    let resp = send_signed_request(&url, &revoke_body, &reader, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_expired_whitelist_cannot_read_storage() {
    reth_tracing::init_test_tracing();
    let admin = PrivateKeySigner::random();
    let reader = PrivateKeySigner::random();
    let (handle, _) = launch_ops_with_admin(admin.address()).await;
    let url = handle.http_url();

    // Admin whitelists reader with very short TTL
    let wl_body = whitelist_key_request(reader.address(), 1, 1);
    let resp = send_signed_request(&url, &wl_body, &admin, "nonce1").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Reader should be rejected — whitelist expired
    let read_body = get_storage_request(CONTRACT_ADDRESS, STORAGE_SLOT, 2);
    let resp = send_signed_request(&url, &read_body, &reader, "nonce2").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Re-whitelist with longer TTL
    let wl_body = whitelist_key_request(reader.address(), 3600, 3);
    let resp = send_signed_request(&url, &wl_body, &admin, "nonce3").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Reader can read again
    let resp = send_signed_request(&url, &read_body, &reader, "nonce4").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
