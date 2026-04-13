#![allow(missing_docs)]

use clap::Parser;
use reth_node_core::args::{EnclaveArgs, ScreeningArgs};
use reth_seismic_cli::{chainspec::SeismicChainSpecParser, Cli};
use reth_seismic_node::{enclave::boot_enclave_and_fetch_keys, node::SeismicNode};

/// Combined CLI extension args for the Seismic node.
///
/// Wraps both enclave and address screening configuration.
#[derive(Debug, Clone, clap::Args)]
struct SeismicExtArgs {
    /// Enclave configuration.
    #[command(flatten)]
    enclave: EnclaveArgs,
    /// Address screening configuration.
    #[command(flatten)]
    screening: ScreeningArgs,
}

impl AsRef<EnclaveArgs> for SeismicExtArgs {
    fn as_ref(&self) -> &EnclaveArgs {
        &self.enclave
    }
}

fn main() {
    // Enable backtraces unless we explicitly set RUST_BACKTRACE
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) =
        Cli::<SeismicChainSpecParser, SeismicExtArgs>::parse().run(|builder, ext| async move {
            // Boot enclave and fetch purpose keys BEFORE building node components
            let purpose_keys = boot_enclave_and_fetch_keys(&ext).await;

            // Store purpose keys in global static storage before building the node.
            // Seismic RPC modules (seismic_ namespace + eth_ overrides) are registered
            // in SeismicAddOns::launch_add_ons, which reads keys via get_purpose_keys().
            reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys);

            let node = builder
                .node(SeismicNode::new(Some(ext.screening)))
                .launch_with_debug_capabilities()
                .await?;
            node.node_exit_future.await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
