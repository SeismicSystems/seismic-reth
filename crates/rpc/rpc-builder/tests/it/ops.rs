//! Ops threshold-auth server tests

use crate::utils::test_address;
use alloy_primitives::{Address, B256};
use ed25519_dalek::{Signer, SigningKey};
use reth_provider::test_utils::NoopProvider;
use reth_rpc::OpsApi;
use reth_rpc_api::OpsApiServer;
use reth_rpc_builder::body_auth::{BodyAuthRpcModule, BodyAuthServerConfig, BodyAuthServerHandle};
use reth_rpc_layer::{
    signature_scheme::ed25519::Ed25519, ThresholdConfig,
};
use reth_tasks::TokioTaskExecutor;
use std::{sync::Arc, time::Duration};

/// Generate a random ed25519 signing key.
fn gen_key() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}

/// Sign `body || nonce` with the given signing key and return hex-encoded signature.
fn sign(key: &SigningKey, body: &[u8], nonce: &str) -> String {
    let mut message = Vec::with_capacity(body.len() + nonce.len());
    message.extend_from_slice(body);
    message.extend_from_slice(nonce.as_bytes());
    let sig = key.sign(&message);
    sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Launch an ops threshold-auth server with the given keys and threshold.
async fn launch_ops(
    keys: &[&SigningKey],
    threshold: usize,
) -> (BodyAuthServerHandle, ThresholdConfig<Ed25519>) {
    let public_keys = keys.iter().map(|k| k.verifying_key()).collect();
    let threshold_config =
        ThresholdConfig::<Ed25519>::new(public_keys, threshold, Duration::from_secs(60));

    let ops_api = OpsApi::new(
        Arc::new(NoopProvider::default()),
        threshold_config.clone(),
        Box::new(TokioTaskExecutor::default()),
    );

    let mut module = BodyAuthRpcModule::empty();
    module.merge_methods(ops_api.into_rpc()).unwrap();

    let server_config = BodyAuthServerConfig::builder(threshold_config.clone())
        .socket_addr(test_address())
        .build();

    let handle = server_config.start(module).await.unwrap();
    (handle, threshold_config)
}

/// Build a JSON-RPC request body for ops_getStorageAt.
fn get_storage_request(address: Address, index: B256, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_getStorageAt",
        "params": [
            format!("{address:?}"),
            format!("{index:?}"),
            "latest"
        ],
        "id": id
    })
    .to_string()
}

/// Build a JSON-RPC request body for ops_addSignerKey.
fn add_signer_key_request(public_key: &[u8], id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_addSignerKey",
        "params": [format!("0x{}", alloy_primitives::hex::encode(public_key))],
        "id": id
    })
    .to_string()
}

/// Build a JSON-RPC request body for ops_removeSignerKey.
fn remove_signer_key_request(public_key: &[u8], id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ops_removeSignerKey",
        "params": [format!("0x{}", alloy_primitives::hex::encode(public_key))],
        "id": id
    })
    .to_string()
}

/// Send a signed request to the ops server.
async fn send_signed_request(
    url: &str,
    body: &str,
    key: &SigningKey,
    request_id: &str,
    nonce: &str,
) -> reqwest::Response {
    let sig = sign(key, body.as_bytes(), nonce);
    reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Request-Id", request_id)
        .header("X-Signature", &sig)
        .header("X-Nonce", nonce)
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_request_without_signature_is_rejected() {
    reth_tracing::init_test_tracing();
    let key1 = gen_key();
    let (handle, _) = launch_ops(&[&key1], 1).await;
    let url = handle.http_url();

    let body = get_storage_request(Address::ZERO, B256::ZERO, 1);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    // Missing signature headers → 400
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_request_with_invalid_signature_is_rejected() {
    reth_tracing::init_test_tracing();
    let key1 = gen_key();
    let unknown = gen_key();
    let (handle, _) = launch_ops(&[&key1], 1).await;
    let url = handle.http_url();

    let body = get_storage_request(Address::ZERO, B256::ZERO, 1);
    let resp = send_signed_request(&url, &body, &unknown, "req1", "nonce1").await;

    // Unknown signer → 401
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_get_storage_at_with_valid_signature() {
    reth_tracing::init_test_tracing();
    let key1 = gen_key();
    let (handle, _) = launch_ops(&[&key1], 1).await;
    let url = handle.http_url();

    let body = get_storage_request(Address::ZERO, B256::ZERO, 1);
    let resp = send_signed_request(&url, &body, &key1, "req1", "nonce1").await;

    // Threshold K=1 met, request forwarded to jsonrpsee → 200
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    // NoopProvider returns zero storage
    assert_eq!(json["result"], format!("{:?}", B256::ZERO));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_threshold_2_of_3() {
    reth_tracing::init_test_tracing();
    let key1 = gen_key();
    let key2 = gen_key();
    let key3 = gen_key();
    let (handle, _) = launch_ops(&[&key1, &key2, &key3], 2).await;
    let url = handle.http_url();

    let body = get_storage_request(Address::ZERO, B256::ZERO, 1);
    let nonce = "nonce1";

    // First signer — 1 of 2, accepted but not forwarded.
    let resp = send_signed_request(&url, &body, &key1, "req1", nonce).await;
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let text = resp.text().await.unwrap();
    assert!(text.contains("1 of 2"), "expected progress message, got: {text}");

    // Second signer — 2 of 2, threshold met, forwarded.
    let resp = send_signed_request(&url, &body, &key2, "req1", nonce).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("result").is_some(), "expected JSON-RPC result");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_add_signer_key() {
    reth_tracing::init_test_tracing();
    let key1 = gen_key();
    let key2 = gen_key();
    let new_key = gen_key();
    let (handle, config) = launch_ops(&[&key1, &key2], 2).await;
    let url = handle.http_url();

    let body = add_signer_key_request(new_key.verifying_key().as_bytes(), 1);
    let nonce = "nonce-add";

    // First signer
    let resp = send_signed_request(&url, &body, &key1, "req-add", nonce).await;
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);

    // Second signer — threshold met
    let resp = send_signed_request(&url, &body, &key2, "req-add", nonce).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], true);

    // Verify the key was actually added.
    let keys = config.public_keys.read().unwrap();
    assert_eq!(keys.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ops_remove_signer_key() {
    reth_tracing::init_test_tracing();
    let key1 = gen_key();
    let key2 = gen_key();
    let (handle, config) = launch_ops(&[&key1, &key2], 2).await;
    let url = handle.http_url();

    let body = remove_signer_key_request(key2.verifying_key().as_bytes(), 1);
    let nonce = "nonce-rm";

    // Both sign to authorize removal
    let resp = send_signed_request(&url, &body, &key1, "req-rm", nonce).await;
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);

    let resp = send_signed_request(&url, &body, &key2, "req-rm", nonce).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"], true);

    // Verify key2 was removed.
    let keys = config.public_keys.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key1.verifying_key());
}
