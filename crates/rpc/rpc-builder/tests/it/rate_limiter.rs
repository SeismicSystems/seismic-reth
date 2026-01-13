//! Integration tests for the Seismic rate limiter middleware.
//!
//! These tests verify that the rate limiter correctly limits RPC requests
//! when integrated with the full RPC server stack.

use crate::utils::{test_address, test_rpc_builder};
use alloy_rpc_types_eth::{Block, Header, Receipt, Transaction, TransactionRequest};
use reth_rpc_builder::{RpcServerConfig, TransportRpcModuleConfig};
use reth_rpc_eth_api::EthApiClient;
use reth_rpc_server_types::RpcModuleSelection;
use reth_seismic_rpc::rate_limiter::{RateLimitConfig, SeismicRateLimiter};

/// Test that rate limiter middleware is properly applied to RPC server
#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limiter_integration() {
    let builder = test_rpc_builder();
    let eth_api = builder.eth_api_builder().enable_storage_apis(true).build();
    let modules =
        builder.build(TransportRpcModuleConfig::set_http(RpcModuleSelection::All), eth_api);

    // Create rate limiter with very restrictive settings for testing
    let rate_limiter = SeismicRateLimiter::new(RateLimitConfig {
        requests_per_second: 2,
        burst_size: 2,
        limited_methods: vec![], // limit all
        exempt_methods: vec![],  // no exemptions
        exempt_ips: vec![],
    });

    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .set_rpc_middleware(rate_limiter)
        .start(&modules)
        .await
        .unwrap();

    let client = handle.http_client().unwrap();

    // First two requests should succeed (burst allows 2)
    let result1 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
    assert!(result1.is_ok(), "First request should succeed");

    let result2 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
    assert!(result2.is_ok(), "Second request should succeed");

    // Third request should be rate limited
    let result3 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
    assert!(result3.is_err(), "Third request should be rate limited");

    // Check that the error is a rate limit error
    let err = result3.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("Rate limited") || err_str.contains("-32029"),
        "Error should indicate rate limiting: {}",
        err_str
    );
}

/// Test that exempt methods bypass rate limiting
#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limiter_exempt_methods() {
    let builder = test_rpc_builder();
    let eth_api = builder.eth_api_builder().enable_storage_apis(true).build();
    let modules =
        builder.build(TransportRpcModuleConfig::set_http(RpcModuleSelection::All), eth_api);

    // Create rate limiter that exempts eth_protocolVersion
    let rate_limiter = SeismicRateLimiter::new(RateLimitConfig {
        requests_per_second: 1,
        burst_size: 1,
        limited_methods: vec![],
        exempt_methods: vec!["eth_protocolVersion".to_string()],
        exempt_ips: vec![],
    });

    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .set_rpc_middleware(rate_limiter)
        .start(&modules)
        .await
        .unwrap();

    let client = handle.http_client().unwrap();

    // Make many requests to the exempt method - all should succeed
    for i in 0..10 {
        let result = EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
        assert!(result.is_ok(), "Exempt method request {} should succeed", i);
    }
}

/// Test that rate limiting works with specific limited methods
#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limiter_specific_methods() {
    let builder = test_rpc_builder();
    let eth_api = builder.eth_api_builder().enable_storage_apis(true).build();
    let modules =
        builder.build(TransportRpcModuleConfig::set_http(RpcModuleSelection::All), eth_api);

    // Only rate limit eth_chainId, leave others unlimited
    let rate_limiter = SeismicRateLimiter::new(RateLimitConfig {
        requests_per_second: 1,
        burst_size: 1,
        limited_methods: vec!["eth_chainId".to_string()],
        exempt_methods: vec![],
        exempt_ips: vec![],
    });

    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .set_rpc_middleware(rate_limiter)
        .start(&modules)
        .await
        .unwrap();

    let client = handle.http_client().unwrap();

    // eth_protocolVersion is not in limited_methods, should be unlimited
    for i in 0..10 {
        let result = EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
        assert!(result.is_ok(), "Non-limited method request {} should succeed", i);
    }

    // eth_chainId is limited, first request succeeds
    let chain_result1 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::chain_id(&client)
            .await;
    assert!(chain_result1.is_ok(), "First chainId request should succeed");

    // Second chainId request should be rate limited
    let chain_result2 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::chain_id(&client)
            .await;
    assert!(chain_result2.is_err(), "Second chainId request should be rate limited");
}

/// Test rate limiter with default configuration
#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limiter_default_config() {
    let builder = test_rpc_builder();
    let eth_api = builder.eth_api_builder().enable_storage_apis(true).build();
    let modules =
        builder.build(TransportRpcModuleConfig::set_http(RpcModuleSelection::All), eth_api);

    // Use default config (100 req/s, 50 burst)
    let rate_limiter = SeismicRateLimiter::with_defaults();

    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .set_rpc_middleware(rate_limiter)
        .start(&modules)
        .await
        .unwrap();

    let client = handle.http_client().unwrap();

    // With default config, we should be able to make many requests
    // eth_chainId is exempt by default
    for i in 0..100 {
        let result =
            EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::chain_id(
                &client,
            )
            .await;
        assert!(result.is_ok(), "Default exempt method request {} should succeed", i);
    }
}

/// Test that rate limiting resets after waiting
#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limiter_token_refill() {
    let builder = test_rpc_builder();
    let eth_api = builder.eth_api_builder().enable_storage_apis(true).build();
    let modules =
        builder.build(TransportRpcModuleConfig::set_http(RpcModuleSelection::All), eth_api);

    // 10 requests per second = 1 token every 100ms
    let rate_limiter = SeismicRateLimiter::new(RateLimitConfig {
        requests_per_second: 10,
        burst_size: 1,
        limited_methods: vec![],
        exempt_methods: vec![],
        exempt_ips: vec![],
    });

    let handle = RpcServerConfig::http(Default::default())
        .with_http_address(test_address())
        .set_rpc_middleware(rate_limiter)
        .start(&modules)
        .await
        .unwrap();

    let client = handle.http_client().unwrap();

    // Exhaust the burst
    let result1 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
    assert!(result1.is_ok(), "First request should succeed");

    let result2 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
    assert!(result2.is_err(), "Second request should be rate limited");

    // Wait for token to refill (>100ms for safety)
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // Should be able to make another request
    let result3 =
        EthApiClient::<TransactionRequest, Transaction, Block, Receipt, Header>::protocol_version(
            &client,
        )
        .await;
    assert!(result3.is_ok(), "Request after refill should succeed");
}
