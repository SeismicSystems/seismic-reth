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
use clap::{value_parser, Args, Parser, Subcommand};
use futures_util::Future;
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::{launcher::FnLauncher, node, stage};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_node_core::{
    args::{init_seismic_rpc_args, EnclaveArgs, LogArgs, SeismicRpcArgs},
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

/// Seismic-specific CLI args carried alongside the node command.
///
/// This is the default `Ext` for [`Cli`]: it bundles the enclave connection args with the Seismic
/// RPC limits so both `--enclave.*` and `--seismic.rpc.*` flags are parsed. `AsRef<EnclaveArgs>`
/// keeps the enclave-boot path unchanged; `AsRef<SeismicRpcArgs>` feeds the RPC-layer signed-read
/// guard.
// TODO(samlaf): the enclave flags still use the bare `--enclave.*` namespace, predating the
// `seismic.*` convention. We probably want to move them under `seismic.enclave.*` so all
// fork-specific flags live under one `seismic.*` namespace.
#[derive(Debug, Clone, Copy, Args, PartialEq, Eq, Default)]
pub struct SeismicNodeArgs {
    /// Enclave connection configuration.
    #[command(flatten)]
    pub enclave: EnclaveArgs,

    /// Seismic-specific RPC limits.
    #[command(flatten)]
    pub seismic_rpc: SeismicRpcArgs,
}

impl AsRef<EnclaveArgs> for SeismicNodeArgs {
    fn as_ref(&self) -> &EnclaveArgs {
        &self.enclave
    }
}

impl AsRef<SeismicRpcArgs> for SeismicNodeArgs {
    fn as_ref(&self) -> &SeismicRpcArgs {
        &self.seismic_rpc
    }
}

/// The main seismic-reth cli interface.
///
/// This is the entrypoint to the executable.
#[derive(Debug, Parser)]
#[command(author, version =version_metadata().short_version.as_ref(), long_version = version_metadata().long_version.as_ref(), about = "Reth", long_about = None)]
pub struct Cli<
    Spec: ChainSpecParser = SeismicChainSpecParser,
    Ext: clap::Args + fmt::Debug = SeismicNodeArgs,
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
    Ext: clap::Args + fmt::Debug + AsRef<EnclaveArgs> + AsRef<SeismicRpcArgs>,
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
        // Handled before tracing init (which logs to stdout): deploy tooling
        // captures this command's stdout and needs it to be the hash alone.
        if matches!(self.command, Commands::GenesisHash) {
            println!("{}", self.chain.genesis_hash());
            return Ok(());
        }

        // add network name to logs dir
        self.logs.log_file_directory =
            self.logs.log_file_directory.join(self.chain.chain().to_string());

        let _guard = self.init_tracing()?;
        info!(target: "reth::cli", "Initialized tracing, debug log directory: {}", self.logs.log_file_directory);

        // Install the prometheus recorder to be sure to record all metrics
        let _ = install_prometheus_recorder();
        let enclave_args = self.enclave;

        // Store the Seismic RPC limits before building the node. The signed-read guard lives in a
        // free function in `reth-seismic-rpc` that has no other channel to the parsed CLI args and
        // reads them back via `seismic_rpc_args()`.
        init_seismic_rpc_args(*AsRef::<SeismicRpcArgs>::as_ref(&enclave_args));

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
            }
            Commands::GenesisHash => unreachable!("handled before tracing init"),
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
    /// Print the genesis block hash for `--chain` and exit.
    ///
    /// Offline: computes `keccak(rlp(header))` from the chain spec without touching a
    /// database or booting the node, so deploy tooling can precompute the
    /// `eth_genesis_hash` that summit's network-params config embeds, before any node
    /// exists.
    ///
    /// This is the chain's block-0 hash — a value *derived* from the genesis file:
    /// state root over the alloc, fork-dependent header fields.
    #[command(name = "genesis-hash")]
    GenesisHash,
}

#[cfg(test)]
mod test {
    use crate::{chainspec::SeismicChainSpecParser, Cli, Commands};
    use clap::Parser;
    use reth_cli_commands::{node::NoArgs, NodeCommand};
    use reth_seismic_chainspec::{SEISMIC_DEV, SEISMIC_DEV_GENESIS_HASH, SEISMIC_DEV_OLD};

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

    #[test]
    fn parse_genesis_hash_command() {
        // The global --chain arg is accepted on either side of the subcommand.
        for args in [
            ["seismic-reth", "genesis-hash", "--chain", "dev"],
            ["seismic-reth", "--chain", "dev", "genesis-hash"],
        ] {
            let cli = Cli::<SeismicChainSpecParser, NoArgs>::try_parse_from(args).unwrap();
            assert!(matches!(cli.command, Commands::GenesisHash));
            assert_eq!(cli.chain.genesis_hash(), SEISMIC_DEV_GENESIS_HASH);
        }
    }

    #[test]
    fn genesis_hash_from_genesis_file() {
        // Deploy passes a genesis *file* (`--chain reth-genesis.json`), while devs
        // use the built-in `--chain dev`; both must agree on the hash. File parsing
        // derives hardforks from the JSON config rather than SEISMIC_DEV_HARDFORKS,
        // so this also fails if the two chain definitions drift apart.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../chainspec/res/genesis/dev.json");
        let cli = Cli::<SeismicChainSpecParser, NoArgs>::try_parse_from([
            "seismic-reth",
            "genesis-hash",
            "--chain",
            path,
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::GenesisHash));
        assert_eq!(cli.chain.genesis_hash(), SEISMIC_DEV_GENESIS_HASH);
    }

    #[test]
    fn genesis_hash_output_format() {
        // Deploy tooling parses stdout as a single lowercase 0x-hex line; pin the
        // Display format the command prints. The value itself changes whenever
        // the dev genesis does, so assert shape, not value.
        let printed = SEISMIC_DEV.genesis_hash().to_string();
        assert_eq!(printed.len(), 66);
        assert!(printed.starts_with("0x"));
        assert!(printed[2..].chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }
}
