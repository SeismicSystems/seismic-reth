#![allow(missing_docs)]

use clap::Parser;
use reth::cli::Cli;
use reth_cli_commands::node::NoArgs;
use reth_enclave::{start_blocking_mock_enclave_server, EnclaveClient};
use reth_node_core::node_config::NodeConfig;
use reth_seismic_cli::chainspec::SeismicChainSpecParser;
use reth_seismic_node::node::SeismicNode;
use reth_seismic_rpc::ext::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer};
use reth_tracing::tracing::*;
use seismic_enclave::{
    boot_genesis_streamlined_async,
    keys::{GetPurposeKeysRequest, GetPurposeKeysResponse},
    rpc::EnclaveApiClient,
};

/// Boot the enclave (or mock server) and fetch purpose keys.
/// This must be called before building the node components.
/// Panics if the enclave cannot be booted or purpose keys cannot be fetched.
async fn boot_enclave_and_fetch_keys<ChainSpec>(
    config: &NodeConfig<ChainSpec>,
) -> GetPurposeKeysResponse {
    let enclave_client = EnclaveClient::builder()
        .ip(config.enclave.enclave_server_addr.to_string())
        .port(config.enclave.enclave_server_port)
        .build()
        .expect("Failed to build enclave client");

    // Boot enclave or start mock server
    if config.enclave.mock_server {
        info!(target: "reth::cli", "Starting mock enclave server");
        let addr = config.enclave.enclave_server_addr;
        let port = config.enclave.enclave_server_port;
        tokio::spawn(async move {
            start_blocking_mock_enclave_server(addr, port).await;
        });
        // Give the mock server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    } else {
        info!(target: "reth::cli", "Booting enclave");
        boot_genesis_streamlined_async(&enclave_client).await.expect("Failed to boot enclave");
    }

    // Fetch purpose keys from enclave - this must succeed or we panic
    info!(target: "reth::cli", "Fetching purpose keys from enclave");
    let purpose_keys = enclave_client
        .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
        .await
        .expect("FATAL: Failed to fetch purpose keys from enclave on boot");

    info!(target: "reth::cli", "Successfully fetched purpose keys from enclave");
    purpose_keys
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<SeismicChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        // Boot enclave and fetch purpose keys BEFORE building node components
        let purpose_keys = boot_enclave_and_fetch_keys(builder.config()).await;

        // Store purpose keys in global static storage before building the node
        reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys);

        // building additional endpoints seismic api
        let seismic_api = SeismicApi::new(builder.config());

        let node = builder
            .node(SeismicNode::default())
            .extend_rpc_modules(move |ctx| {
                // replace eth_ namespace
                ctx.modules.replace_configured(
                    EthApiExt::new(ctx.registry.eth_api().clone(), EnclaveClient::default())
                        .into_rpc(),
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
