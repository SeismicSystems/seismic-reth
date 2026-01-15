//! Seismic-Reth CLI implementation.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// Seismic chain specification parser.
pub mod chainspec;

use chainspec::SeismicChainSpecParser;
use clap::{value_parser, Parser, Subcommand};
use futures_util::Future;
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::{launcher::FnLauncher, node, stage, prune, init_state, db, dump_genesis, config_cmd, init_cmd, p2p, re_execute, recover};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_node_core::{
    args::{EnclaveArgs, LogArgs},
    version::version_metadata,
};
use reth_node_ethereum::consensus::EthBeaconConsensus;
use reth_seismic_node::{
    enclave::boot_enclave_and_fetch_keys,
    node::SeismicNode,
    purpose_keys::{get_purpose_keys, init_purpose_keys},
    SeismicEvmConfig,
};
use reth_tracing::FileWorkerGuard;
// This allows us to manually enable node metrics features, required for proper jemalloc metric
// reporting
use reth_node_metrics as _;
use reth_node_metrics::recorder::install_prometheus_recorder;
use std::{ffi::OsString, fmt, sync::Arc};
use tracing::info;

/// The main seismic-reth cli interface.
///
/// This is the entrypoint to the executable.
#[derive(Debug, Parser)]
#[command(author, version =version_metadata().short_version.as_ref(), long_version = version_metadata().long_version.as_ref(), about = "Reth", long_about = None)]
pub struct Cli<
    Spec: ChainSpecParser = SeismicChainSpecParser,
    Ext: clap::Args + fmt::Debug = EnclaveArgs,
> {
    /// The command to run
    #[command(subcommand)]
    pub command: Commands<Spec, Ext>,

    /// The chain this node is running.
    ///
    /// Possible values are either a built-in chain or the path to a chain specification file.
    #[arg(
        long,
        value_name = "CHAIN_OR_PATH",
        long_help = Spec::help_message(),
        default_value = Spec::SUPPORTED_CHAINS[0],
        value_parser = Spec::parser(),
        global = true,
    )]
    pub chain: Arc<Spec::ChainSpec>,

    /// Add a new instance of a node.
    ///
    /// Configures the ports of the node to avoid conflicts with the defaults.
    /// This is useful for running multiple nodes on the same machine.
    ///
    /// Max number of instances is 200. It is chosen in a way so that it's not possible to have
    /// port numbers that conflict with each other.
    ///
    /// Changes to the following port numbers:
    /// - `DISCOVERY_PORT`: default + `instance` - 1
    /// - `AUTH_PORT`: default + `instance` * 100 - 100
    /// - `HTTP_RPC_PORT`: default - `instance` + 1
    /// - `WS_RPC_PORT`: default + `instance` * 2 - 2
    #[arg(long, value_name = "INSTANCE", global = true, default_value_t = 1, value_parser = value_parser!(u16).range(..=200))]
    pub instance: u16,

    /// The logging configuration for the CLI.
    #[command(flatten)]
    pub logs: LogArgs,

    /// Enclave configuration for Seismic.
    #[command(flatten)]
    pub enclave: Ext,
}

impl Cli {
    /// Parsers only the default CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Parsers only the default CLI arguments from the given iterator
    pub fn try_parse_args_from<I, T>(itr: I) -> Result<Self, clap::error::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        Self::try_parse_from(itr)
    }
}

impl<C, Ext> Cli<C, Ext>
where
    C: ChainSpecParser<ChainSpec = ChainSpec>,
    Ext: clap::Args + fmt::Debug + AsRef<EnclaveArgs>,
{
    /// Execute the configured cli command.
    ///
    /// This accepts a closure that is used to launch the node via the
    /// [`NodeCommand`](reth_cli_commands::node::NodeCommand).
    pub fn run<L, Fut>(self, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, C::ChainSpec>>, Ext) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        self.with_runner(CliRunner::try_default_runtime()?, launcher)
    }

    /// Execute the configured cli command with the provided [`CliRunner`].
    pub fn with_runner<L, Fut>(mut self, runner: CliRunner, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, C::ChainSpec>>, Ext) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        // add network name to logs dir
        self.logs.log_file_directory =
            self.logs.log_file_directory.join(self.chain.chain().to_string());

        let _guard = self.init_tracing()?;
        info!(target: "reth::cli", "Initialized tracing, debug log directory: {}", self.logs.log_file_directory);

        // Install the prometheus recorder to be sure to record all metrics
        let _ = install_prometheus_recorder();
        let enclave_args = self.enclave;

        match self.command {
            Commands::Node(command) => runner.run_command_until_exit(|ctx| {
                command.execute(
                    ctx,
                    FnLauncher::new::<C, Ext>(async move |builder, ext| {
                        launcher(builder, ext).await
                    }),
                )
            }),
            Commands::Stage(command) => {
                runner.run_command_until_exit(|ctx| async move {
                    // For Stage commands, boot the enclave and fetch purpose keys first
                    let purpose_keys_response = boot_enclave_and_fetch_keys(&enclave_args).await;

                    // Initialize purpose keys in global storage
                    init_purpose_keys(purpose_keys_response);

                    // Create components with the initialized purpose keys
                    let components = |spec: Arc<C::ChainSpec>| {
                        let purpose_keys = get_purpose_keys();
                        (
                            SeismicEvmConfig::new(spec.clone(), purpose_keys),
                            EthBeaconConsensus::new(spec),
                        )
                    };

                    // Execute the stage command
                    command.execute::<SeismicNode, _>(ctx, components).await
                })
            },
            Commands::Prune(command) => {
                runner.run_until_ctrl_c(command.execute::<SeismicNode>())
            },
            Commands::InitState(command) => {
                runner.run_until_ctrl_c(command.execute::<SeismicNode>())
            },
            Commands::Init(command) => {
                runner.run_until_ctrl_c(command.execute::<SeismicNode>())
            },
            Commands::Db(command) => {
                runner.run_until_ctrl_c(command.execute::<SeismicNode>())
            },
            Commands::DumpGenesis(command) => {
                runner.run_until_ctrl_c(command.execute())
            },
            Commands::Config(command) => {
                runner.run_until_ctrl_c(command.execute())
            },
            Commands::P2P(command) => {
                runner.run_until_ctrl_c(command.execute::<SeismicNode>())
            },
            Commands::ReExecute(command) => {
                runner.run_command_until_exit(|_ctx| async move {
                    // For ReExecute commands, boot the enclave and fetch purpose keys first
                    let purpose_keys_response = boot_enclave_and_fetch_keys(&enclave_args).await;

                    // Initialize purpose keys in global storage
                    init_purpose_keys(purpose_keys_response);

                    // Create components with the initialized purpose keys
                    let components = |spec: Arc<C::ChainSpec>| {
                        let purpose_keys = get_purpose_keys();
                        (
                            SeismicEvmConfig::new(spec.clone(), purpose_keys),
                            EthBeaconConsensus::new(spec),
                        )
                    };

                    // Execute the re-execute command
                    command.execute::<SeismicNode>(components).await
                })
            },
            Commands::Recover(command) => {
                runner.run_command_until_exit(|ctx| command.execute::<SeismicNode>(ctx))
            },
        }
    }

    /// Initializes tracing with the configured options.
    ///
    /// If file logging is enabled, this function returns a guard that must be kept alive to ensure
    /// that all logs are flushed to disk.
    pub fn init_tracing(&self) -> eyre::Result<Option<FileWorkerGuard>> {
        let guard = self.logs.init_tracing()?;
        Ok(guard)
    }
}

/// Commands to be executed
#[derive(Debug, Subcommand)]
pub enum Commands<C: ChainSpecParser, Ext: clap::Args + fmt::Debug> {
    /// Start the node
    #[command(name = "node")]
    Node(Box<node::NodeCommand<C, Ext>>),
    /// Manipulate individual stages.
    #[command(name = "stage")]
    Stage(stage::Command<C>),
    /// Prune according to the configuration without any limits
    #[command(name = "prune")]
    Prune(prune::PruneCommand<C>),
    /// Command that initializes a node from the genesis file.
    #[command(name = "init_state")]
    InitState(init_state::InitStateCommand<C>),
    /// Database debugging utilities and operations
    #[command(name = "db")]
    Db(db::Command<C>),
    /// Command that dumps genesis block JSON configuration to stdout.
    #[command(name = "dump_genesis")]
    DumpGenesis(dump_genesis::DumpGenesisCommand<C>),
    /// Command that shows configs
    #[command(name = "config_cmd")]
    Config(config_cmd::Command),
    /// Command that initializes a node from the genesis file.
    #[command(name = "init_cmd")]
    Init(init_cmd::InitCommand<C>),
    /// P2P debugging utilities
    #[command(name = "p2p")]
    P2P(Box<p2p::Command<C>>), 
      /// Command that re-executes blocks in parallel 
    #[command(name = "re_execute")]
    ReExecute(re_execute::Command<C>),
    /// Reth recover command
    #[command(name = "recover")]
    Recover(recover::Command<C>)
}

#[cfg(test)]
mod test {
    use crate::chainspec::SeismicChainSpecParser;
    use clap::Parser;
    use reth_cli_commands::{node::NoArgs, NodeCommand};
    use reth_seismic_chainspec::{SEISMIC_DEV, SEISMIC_DEV_OLD};

    #[test]
    fn parse_dev() {
        let cmd =
            NodeCommand::<SeismicChainSpecParser, NoArgs>::parse_from(["seismic-reth", "--dev"]);
        let chain = SEISMIC_DEV.clone();
        assert_eq!(cmd.chain.chain, chain.chain);
        assert_eq!(cmd.chain.genesis_hash(), chain.genesis_hash());
        assert_eq!(
            cmd.chain.paris_block_and_final_difficulty,
            chain.paris_block_and_final_difficulty
        );
        assert_eq!(cmd.chain.hardforks, chain.hardforks);

        assert!(cmd.rpc.http);
        assert!(cmd.network.discovery.disable_discovery);

        assert!(cmd.dev.dev);
    }

    #[test]
    fn parse_dev_old() {
        // TODO: remove this once we launch devnet with consensus
        let cmd = NodeCommand::<SeismicChainSpecParser, NoArgs>::parse_from([
            "seismic-reth",
            "--chain",
            "dev-old",
            "--http",
            "-d",
        ]);
        let chain = SEISMIC_DEV_OLD.clone();
        assert_eq!(cmd.chain.chain, chain.chain);
        assert_eq!(cmd.chain.genesis_hash(), chain.genesis_hash());
        assert_eq!(
            cmd.chain.paris_block_and_final_difficulty,
            chain.paris_block_and_final_difficulty
        );
        assert_eq!(cmd.chain.hardforks, chain.hardforks);

        assert!(cmd.rpc.http);
        assert!(cmd.network.discovery.disable_discovery);
    }
}
