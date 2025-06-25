#![allow(missing_docs)]

use clap::Parser;
use reth::cli::Cli;
use reth_cli_commands::node::NoArgs;
use reth_enclave::{start_blocking_mock_enclave_server, EnclaveClient};
use reth_node_builder::{EngineNodeLauncher, TreeConfig};
use reth_seismic_cli::chainspec::SeismicChainSpecParser;
use reth_seismic_node::node::SeismicNode;
use reth_seismic_rpc::ext::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer};
use reth_tracing::tracing::*;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<SeismicChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        let engine_tree_config = TreeConfig::default();

        // building additional endpoints seismic api
        let seismic_api = SeismicApi::new(builder.config());

        let node = builder
            .node(SeismicNode::default())
            .on_node_started(move |ctx| {
                if ctx.config.enclave.mock_server {
                    ctx.task_executor.spawn(async move {
                        start_blocking_mock_enclave_server(
                            ctx.config.enclave.enclave_server_addr,
                            ctx.config.enclave.enclave_server_port,
                        )
                        .await;
                    });
                }
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
