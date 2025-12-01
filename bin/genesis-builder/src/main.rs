//! Genesis builder CLI tool for adding contracts to genesis files

use clap::Parser;
use reth_genesis_builder::{builder::GenesisBuilder, error::BuilderError, genesis, manifest};
use std::path::PathBuf;
use tracing::info;
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
}

/// Main function for building genesis files
fn main() -> Result<(), BuilderError> {
    // Initialize tracing subscriber to read RUST_LOG env variable
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    info!("Loading manifest: {}", args.manifest.display());
    let manifest_data = manifest::load_manifest(&args.manifest)?;
    info!("Found {} contracts to deploy", manifest_data.contracts.len());

    info!("Loading genesis: {}", args.genesis.display());
    let genesis_data = genesis::load_genesis(&args.genesis)?;
    info!("   Current allocations: {}", genesis_data.alloc.len());

    let builder = GenesisBuilder::new(manifest_data, genesis_data)?;
    let updated_genesis = builder.build()?;

    let output_path = args.output.unwrap_or(args.genesis.clone());
    info!("Writing genesis: {}", output_path.display());
    genesis::write_genesis(&updated_genesis, &output_path)?;

    info!("Genesis build complete!");
    info!("   Total allocations: {}", updated_genesis.alloc.len());

    Ok(())
}
