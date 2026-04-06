#![allow(missing_docs)]

use clap::Parser;
use reth_seismic_cli::{chainspec::SeismicChainSpecParser, Cli};
use reth_seismic_node::{enclave::boot_enclave_and_fetch_keys, node::SeismicNode};

fn main() {
    // Enable backtraces unless we explicitly set RUST_BACKTRACE
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) = Cli::<SeismicChainSpecParser>::parse().run(|builder, encl| async move {
        // Boot enclave and fetch purpose keys BEFORE building node components
        let purpose_keys = boot_enclave_and_fetch_keys(&encl).await;

        // Store purpose keys in global static storage before building the node.
        // Seismic RPC modules (seismic_ namespace + eth_ overrides) are registered
        // in SeismicAddOns::launch_add_ons, which reads keys via get_purpose_keys().
        reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys);

        let node = builder.node(SeismicNode::default()).launch_with_debug_capabilities().await?;
        node.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
