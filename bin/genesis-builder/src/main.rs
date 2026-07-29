//! Genesis builder CLI tool for adding contracts to genesis files

use clap::Parser;
use reth_genesis_builder::{builder::GenesisBuilder, error::BuilderError, genesis, manifest};
use std::{path::PathBuf, process};
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Command line arguments
#[derive(Parser)]
#[command(name = "genesis-builder")]
#[command(version)]
#[command(about = "Build genesis files with contracts from GitHub", long_about = None)]
struct Args {
    /// Path to genesis manifest TOML file
    #[arg(
        long,
        value_name = "FILE",
        default_value = "crates/seismic/chainspec/res/genesis/manifest.toml"
    )]
    manifest: PathBuf,

    /// Fetch artifacts from this base URL instead of from the commit the
    /// manifest pins. Only for working with local files before they are pushed to github.
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,

    /// Path to genesis JSON file to modify
    #[arg(
        long,
        value_name = "FILE",
        default_value = "crates/seismic/chainspec/res/genesis/dev.json"
    )]
    genesis: PathBuf,

    /// Optional output path (defaults to modifying input genesis file in-place)
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Verify the genesis file already matches the manifest instead of writing
    /// it, exiting non-zero on any drift
    #[arg(long)]
    check: bool,

    /// say "yes" to every overwrite question
    #[arg(short = 'y', long)]
    yes_overwrite: bool,
}

/// Main function for building genesis files
fn main() -> Result<(), BuilderError> {
    // Initialize tracing subscriber to read RUST_LOG env variable, defaulting to
    // info so a run always reports which artifacts it fetched
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    info!("Loading manifest: {}", args.manifest.display());
    let manifest_data = manifest::load_manifest(&args.manifest)?;
    info!("Found {} contracts to deploy", manifest_data.contracts.len());

    info!("Loading genesis: {}", args.genesis.display());
    let genesis_data = genesis::load_genesis(&args.genesis)?;
    info!("   Current allocations: {}", genesis_data.alloc.len());

    // Nothing is written in check mode, so a collision has nothing to confirm
    let yes_overwrite = args.yes_overwrite || args.check;
    let mut builder = GenesisBuilder::new(manifest_data, genesis_data, yes_overwrite)?;
    if let Some(base_url) = args.base_url {
        builder = builder.with_base_url(base_url);
    }
    let updated_genesis = builder.build()?;

    let output_path = args.output.unwrap_or(args.genesis);

    if args.check {
        if genesis::is_current(&updated_genesis, &output_path)? {
            info!("{} matches the manifest", output_path.display());
            return Ok(());
        }

        error!(
            "{} is out of date with the manifest: rerun genesis-builder and commit the result",
            output_path.display()
        );
        process::exit(1);
    }

    info!("Writing genesis: {}", output_path.display());
    genesis::write_genesis(&updated_genesis, &output_path)?;

    info!("Genesis build complete!");
    info!("   Total allocations: {}", updated_genesis.alloc.len());

    Ok(())
}
