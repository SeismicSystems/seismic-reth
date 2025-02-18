#![allow(missing_docs)]

use reth_cli_commands::node::NoArgs;
use reth_enclave::{BuildableServer, MockEnclaveServer};
use reth_node_builder::{engine_tree_config::TreeConfig, EngineNodeLauncher};
use reth_provider::providers::BlockchainProvider2;
use reth_tracing::tracing::*;
use seismic_node::chainspec::SeismicChainSpecParser;
use seismic_rpc_api::rpc::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer};

fn main() {
    use clap::Parser;
    use reth::cli::Cli;
    use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};

    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<SeismicChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        let engine_tree_config = TreeConfig::default();
        let node = builder
            .with_types_and_provider::<EthereumNode, BlockchainProvider2<_>>()
            .with_components(EthereumNode::components())
            .with_add_ons(EthereumAddOns::default())
            .on_node_started(move |ctx| {
                if ctx.config.enclave.mock_server {
                    ctx.task_executor.spawn(async move {
                        let enclave_server = MockEnclaveServer::new_from_addr_port(
                            ctx.config.enclave.enclave_server_addr.to_string(),
                            ctx.config.enclave.enclave_server_port,
                        );

                        let addr = enclave_server.addr();

                        match enclave_server.start().await {
                            Ok(handle) => {
                                handle.stopped().await;
                            }
                            Err(err) => {
                                let err = eyre::eyre!(
                                    "Failed to start mock enclave server at {}: {}",
                                    addr,
                                    err
                                );
                                error!("{:?}", err);
                            }
                        }
                    });
                }
                Ok(())
            })
            .extend_rpc_modules(move |ctx| {
                // replace eth_ namespace
                ctx.modules.replace_configured(
                    EthApiExt::new(ctx.registry.eth_api().clone()).into_rpc(),
                )?;

                // add seismic_ namespace
                let seismic_api = SeismicApi::new();
                ctx.modules.merge_configured(seismic_api.into_rpc())?;
                info!(target: "reth::cli", "seismic api configured");
                Ok(())
            })
            .launch_with_fn(|builder| {
                let launcher = EngineNodeLauncher::new(
                    builder.task_executor().clone(),
                    builder.config().datadir(),
                    engine_tree_config,
                );
                builder.launch_with(launcher)
            })
            .await?;
        node.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
