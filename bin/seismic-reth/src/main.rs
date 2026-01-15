#![allow(missing_docs)]

use clap::Parser;
use reth_seismic_cli::{chainspec::SeismicChainSpecParser, Cli};
use reth_seismic_node::{enclave::boot_enclave_and_fetch_keys, node::SeismicNode};
use reth_seismic_rpc::ext::{EthApiExt, EthApiOverrideServer, SeismicApi, SeismicApiServer};
use reth_tracing::tracing::*;

fn main() {
    // Enable backtraces unless we explicitly set RUST_BACKTRACE
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    reth_cli_util::sigsegv_handler::install();

    if let Err(err) =
        Cli::<SeismicChainSpecParser>::parse().run(|builder, enclave_args| async move {
            // Boot enclave and fetch purpose keys BEFORE building node components
            let purpose_keys = boot_enclave_and_fetch_keys(&enclave_args).await;

            // Store purpose keys in global static storage before building the node
            reth_seismic_node::purpose_keys::init_purpose_keys(purpose_keys.clone());

            // building additional endpoints seismic api
            let seismic_api = SeismicApi::new(purpose_keys.clone());

            let node = builder
                .node(SeismicNode::default())
                .extend_rpc_modules(move |ctx| {
                    // replace eth_ namespace
                    ctx.modules.replace_configured(
                        EthApiExt::new(ctx.registry.eth_api().clone(), purpose_keys.clone())
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
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
