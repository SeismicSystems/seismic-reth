#![allow(missing_docs)]

use clap::Parser;
use reth::cli::Cli;
use reth_cli_commands::node::NoArgs;
use reth_enclave::{start_blocking_mock_enclave_server, EnclaveClient};
use reth_seismic_cli::chainspec::SeismicChainSpecParser;
use reth_seismic_node::node::SeismicNode;
use reth_seismic_rpc::ext::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer};
use reth_tracing::tracing::*;
use seismic_enclave::{boot_genesis_streamlined_async, keys::GetPurposeKeysRequest};
use reth_enclave::SyncEnclaveApiClient;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<SeismicChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        // building additional endpoints seismic api
        let seismic_api = SeismicApi::new(builder.config());

        let node = builder
            .node(SeismicNode::default())
            .on_node_started(move |ctx| {
                let enclave_client = EnclaveClient::builder()
                    .ip(ctx.config.enclave.enclave_server_addr.to_string())
                    .port(ctx.config.enclave.enclave_server_port)
                    .build()
                    .expect("Failed to build enclave client");

                match ctx.config.enclave.mock_server {
                    true => {
                        ctx.task_executor.spawn(async move {
                            start_blocking_mock_enclave_server(
                                ctx.config.enclave.enclave_server_addr,
                                ctx.config.enclave.enclave_server_port,
                            )
                            .await;
                        });
                        // Give the mock server a moment to start
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    false => {
                        // Boots the enclave with random keys (aka enclave genesis boot)
                        // Long term this should be removed and node operators should handle booting
                        // We block here because we need the enclave ready before fetching keys
                        tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async {
                                boot_genesis_streamlined_async(&enclave_client)
                                    .await
                                    .expect("Failed to boot enclave");
                            })
                        });
                    }
                }

                // Fetch purpose keys from enclave - this must succeed or we panic
                let purpose_keys = enclave_client
                    .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
                    .expect("FATAL: Failed to fetch purpose keys from enclave on boot");

                // Store purpose keys in global static storage
                reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys);
                info!(target: "reth::cli", "Successfully fetched and stored purpose keys from enclave");

                Ok(())
            })
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
