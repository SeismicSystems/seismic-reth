//! Genesis builder CLI tool for adding contracts to genesis files

use clap::Parser;
use reth_genesis_builder::{builder::GenesisBuilder, error::BuilderError, genesis, manifest};
use std::path::PathBuf;

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
    let args = Args::parse();

    // Load manifest
    println!("Loading manifest: {}", args.manifest.display());
    let manifest_data = manifest::load_manifest(&args.manifest)?;
    println!("Found {} contracts to deploy", manifest_data.contracts.len());
    println!();

    // Load genesis
    println!("Loading genesis: {}", args.genesis.display());
    let genesis_data = genesis::load_genesis(&args.genesis)?;
    println!("   Current allocations: {}", genesis_data.alloc.len());
    println!();

    // Build genesis with contracts
    let builder = GenesisBuilder::new(manifest_data, genesis_data)?;
    let updated_genesis = builder.build()?;

    // Write output
    let output_path = args.output.unwrap_or(args.genesis.clone());
    println!();
    println!("Writing genesis: {}", output_path.display());
    genesis::write_genesis(&updated_genesis, &output_path)?;

    println!();
    println!("Genesis build complete!");
    println!("   Total allocations: {}", updated_genesis.alloc.len());

    Ok(())
}
