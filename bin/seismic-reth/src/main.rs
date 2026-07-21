#![allow(missing_docs)]

use clap::Parser;
use reth_seismic_cli::{chainspec::SeismicChainSpecParser, Cli};
use reth_seismic_node::{keys_source::fetch_purpose_keys, node::SeismicNode};

fn main() {
    // Enable backtraces unless we explicitly set RUST_BACKTRACE
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) = Cli::<SeismicChainSpecParser>::parse().run(|builder, ext| async move {
        // Fetch purpose keys BEFORE building node components
        let purpose_keys = fetch_purpose_keys(&ext).await;

        // Store purpose keys in global static storage as a fallback for code
        // paths that cannot yet receive keys structurally (e.g. CLI stage command).
        // Seismic RPC modules (seismic_ namespace + eth_ overrides) are registered
        // in SeismicAddOns::launch_add_ons, which reads keys via get_purpose_keys().
        reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys.clone());

        // Inject purpose keys structurally into SeismicNode so they flow
        // through the node builder lifecycle without relying on the global.
        let node =
            builder.node(SeismicNode::new(purpose_keys)).launch_with_debug_capabilities().await?;
        node.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
