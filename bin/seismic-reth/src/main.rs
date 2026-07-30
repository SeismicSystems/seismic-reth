#![allow(missing_docs)]

use clap::Parser;
use reth_node_core::args::PurposeKeysArgs;
use reth_seismic_cli::{chainspec::SeismicChainSpecParser, Cli};
use reth_seismic_keys::PurposeKeyring;
use reth_seismic_node::{keys_source::fetch_purpose_keys, node::SeismicNode};
use std::sync::Arc;

fn main() {
    // Enable backtraces unless we explicitly set RUST_BACKTRACE
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) = Cli::<SeismicChainSpecParser>::parse().run(|builder, ext| async move {
        // Fetch the epoch-0 purpose keys BEFORE building node components and seed the
        // keyring with them. The rotation watcher fetches later epochs at runtime as
        // on-chain announcements appear (docs/design/purpose-key-rotation.md).
        let purpose_keys = fetch_purpose_keys(&ext).await;
        let keyring = Arc::new(PurposeKeyring::single_epoch(purpose_keys));

        // Store the keyring in global static storage as a fallback for code paths
        // that cannot yet receive it structurally (e.g. CLI stage command).
        // Seismic RPC modules (seismic_ namespace + eth_ overrides) are registered
        // in SeismicAddOns::launch_add_ons, which reads it via get_purpose_keyring().
        reth_seismic_node::purpose_keys::init_purpose_keyring(keyring.clone());

        // Inject the keyring structurally into SeismicNode so it flows through the
        // node builder lifecycle without relying on the global; the purpose-key args
        // let the rotation watcher fetch newly announced epochs from the custodian.
        let purpose_keys_args = AsRef::<PurposeKeysArgs>::as_ref(&ext).clone();
        let node = builder
            .node(SeismicNode::new(keyring, purpose_keys_args))
            .launch_with_debug_capabilities()
            .await?;
        node.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
