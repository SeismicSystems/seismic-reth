#![allow(missing_docs)]

use std::net::SocketAddr;

use clap::Parser;
use jsonrpsee_http_client::HttpClientBuilder;
use reth::cli::Cli;
use reth_cli_commands::node::NoArgs;
use reth_node_builder::Node;
use reth_node_core::node_config::NodeConfig;
use reth_seismic_cli::chainspec::SeismicChainSpecParser;
use reth_seismic_node::node::SeismicNode;
use reth_seismic_rpc::{
    ext::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer},
    rate_limiter::{RateLimitConfig, SeismicRateLimiter}, // ADD THIS
};
use reth_tracing::tracing::*;

use seismic_enclave::{
    api::TdxQuoteRpcClient as _, mock::start_mock_server, GetPurposeKeysResponse,
};

/// Boot the enclave (or mock server) and fetch purpose keys.
/// This must be called before building the node components.
/// Panics if the enclave cannot be booted or purpose keys cannot be fetched.
#[allow(clippy::expect_used)] // Intentional panic on startup failure - enclave is required
#[allow(clippy::panic)] // Intentional panic on fetching keys failure - enclave keys are required
async fn boot_enclave_and_fetch_keys<ChainSpec>(
    config: &NodeConfig<ChainSpec>,
) -> GetPurposeKeysResponse {
    // Boot enclave or start mock server
    if config.enclave.mock_server {
        info!(target: "reth::cli", "Starting mock enclave server");
        let addr = config.enclave.enclave_server_addr;
        let port = config.enclave.enclave_server_port;
        tokio::spawn(async move {
            start_mock_server(SocketAddr::new(addr, port))
                .await
                .expect("Failed to start mock enclave server");
        });
        // Give the mock server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    let enclave_client = HttpClientBuilder::default()
        .build(format!(
            "http://{}:{}",
            config.enclave.enclave_server_addr, config.enclave.enclave_server_port
        ))
        .expect("Failed to build enclave client");

    // Fetch purpose keys from enclave - this must succeed or we panic
    info!(target: "reth::cli", "Fetching purpose keys from enclave");
    let mut failures = 0;
    while failures <= config.enclave.retries {
        match enclave_client.get_purpose_keys(0).await {
            Ok(purpose_keys) => {
                info!(target: "reth::cli", "Successfully fetched purpose keys from enclave");
                return purpose_keys;
            }
            Err(e) => {
                warn!(target: "reth::cli", "Failure to fetch purpose keys {}/{}: {}", failures, config.enclave.retries, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    config.enclave.retry_seconds.into(),
                ))
                .await;
                failures += 1;
            }
        }
    }
    panic!("FATAL: Failed to fetch purpose keys from enclave on boot after {} failures", failures);
}

fn main() {
    // Enable backtraces unless we explicitly set RUST_BACKTRACE
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) = Cli::<SeismicChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        // Boot enclave and fetch purpose keys BEFORE building node components
        let purpose_keys = boot_enclave_and_fetch_keys(builder.config()).await;

        // Store purpose keys in global static storage before building the node
        reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys.clone());

        // building additional endpoints seismic api
        let seismic_api = SeismicApi::new(purpose_keys.clone());

        // Configure rate limiting
        let rate_limiter = SeismicRateLimiter::new(RateLimitConfig {
            requests_per_second: 100, // 100 requests per second per IP
            burst_size: 50,           // Allow bursts of up to 50 requests
            limited_methods: vec![],  // Empty = limit all methods (except exempt)
            exempt_methods: vec![
                "eth_chainId".to_string(),
                "eth_blockNumber".to_string(),
                "net_version".to_string(),
                "web3_clientVersion".to_string(),
                "seismic_getTeePublicKey".to_string(),
            ],
            exempt_ips: vec![
                // Add internal service IPs here if needed
                // "127.0.0.1".parse().unwrap(),
            ],
        });

        info!(target: "reth::cli", "Rate limiting configured: {} req/s, burst {}", 
            100, 50);

        let seismic_node = SeismicNode::default();
        let add_ons = seismic_node.add_ons().layer_rpc_middleware(rate_limiter);

        let node = builder
            .with_types::<SeismicNode>()
            .with_components(seismic_node.components_builder())
            .with_add_ons(add_ons)
            .extend_rpc_modules(move |ctx| {
                // replace eth_ namespace
                ctx.modules.replace_configured(
                    EthApiExt::new(ctx.registry.eth_api().clone(), purpose_keys.clone()).into_rpc(),
                )?;

                // add seismic_ namespace
                ctx.modules.merge_configured(seismic_api.into_rpc())?;
                info!(target: "reth::cli", "seismic api configured");
                Ok(())
            })
            .launch_with_debug_capabilities()
            .await?;
        node.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
