#![allow(missing_docs)]

/// clap [Args] for Engine related arguments.
use clap::Args;
use reth::chainspec::EthereumChainSpecParser;
use reth_cli_commands::node::NoArgs;
use reth_node_builder::DefaultNodeLauncher;
use reth_provider::providers::BlockchainProvider;
use reth_seismic_node::rpc::{SeismicApi, SeismicApiServer};
use reth_tee::mock::MockTeeServer;
use tracing::info;

/// Parameters for configuring the engine
#[derive(Debug, Clone, Args, PartialEq, Eq, Default)]
#[command(next_help_heading = "Engine")]
pub struct EngineArgs {
    /// Enable the engine2 experimental features on reth binary
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,
}

fn main() {
    use clap::Parser;
    use reth::cli::Cli;
    use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};

    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<EthereumChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        let node = builder
            .with_types_and_provider::<EthereumNode, BlockchainProvider<_>>()
            .with_components(EthereumNode::components())
            .with_add_ons(EthereumAddOns::default())
            .on_node_started(move |ctx| {
                if ctx.config.tee.mock_server {
                    ctx.task_executor.spawn(async move {
                        let tee_server_url = format!(
                            "{}:{}",
                            ctx.config.tee.tee_server_addr, ctx.config.tee.tee_server_port
                        );
                        let tee_server = MockTeeServer::new(&tee_server_url);
                        tee_server
                            .run()
                            .await
                            .expect("mock tee server failed to start in dev mode");
                    });
                    info!(target: "reth::cli", "mock tee server started in dev mode");
                }
                Ok(())
            })
            .extend_rpc_modules(move |ctx| {
                let seismic_api = SeismicApi::new();
                ctx.modules.merge_configured(seismic_api.into_rpc())?;
                info!(target: "reth::cli", "seismic api configured");
                Ok(())
            })
            .launch_with_fn(|builder| {
                let launcher = DefaultNodeLauncher::new(
                    builder.task_executor().clone(),
                    builder.config().datadir(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_parse_engine_args() {
        let default_args = EngineArgs::default();
        let args = CommandParser::<EngineArgs>::parse_from(["reth"]).args;
        assert_eq!(args, default_args);
    }
}
