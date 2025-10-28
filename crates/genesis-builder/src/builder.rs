use crate::{
    artifact::ArtifactLoader,
    error::{BuilderError, Result},
    types::{Genesis, GenesisAccount, Manifest},
};
use alloy_primitives::{hex, Address};
use tracing::info;

/// Default nonce for the genesis file
pub const DEFAULT_NONCE: &str = "0x1";

/// Default balance for the genesis file
pub const DEFAULT_BALANCE: &str = "0x0";

/// Builder for constructing genesis files with contracts
#[derive(Debug)]
pub struct GenesisBuilder {
    /// Manifest containing the contracts to deploy
    manifest: Manifest,
    /// Genesis file to build
    genesis: Genesis,
    /// Loader for fetching contract artifacts
    loader: ArtifactLoader,
    /// Number of contracts added to the genesis file
    contracts_added: usize,
}

impl GenesisBuilder {
    /// Create a new genesis builder
    pub fn new(manifest: Manifest, genesis: Genesis) -> Result<Self> {
        let loader = ArtifactLoader::new()?;

        Ok(Self { manifest, genesis, loader, contracts_added: 0 })
    }

    /// Execute the build process
    pub fn build(mut self) -> Result<Genesis> {
        info!(
            "Building genesis with {} contracts from {}",
            self.manifest.contracts.len(),
            self.manifest.metadata.base_url()
        );

        for (name, config) in &self.manifest.contracts.clone() {
            self.add_contract(name, config)?;
        }

        info!("Added {} contracts to genesis", self.contracts_added);
        Ok(self.genesis)
    }

    /// Add a single contract to genesis
    fn add_contract(&mut self, name: &str, config: &crate::types::ContractConfig) -> Result<()> {
        let url = format!(
            "{}/{}",
            self.manifest.metadata.base_url().trim_end_matches('/'),
            config.artifact.trim_start_matches('/')
        );

        let artifact = self.loader.load_artifact(&url)?;

        let address = parse_address(&config.address)?;

        if self.genesis.alloc.contains_key(&address) {
            return Err(BuilderError::AddressCollision(format!("{} ({})", name, config.address)));
        }

        let account = GenesisAccount {
            code: Some(format!("0x{}", hex::encode(&artifact.bytecode))),
            balance: DEFAULT_BALANCE.to_string(),
            nonce: Some(DEFAULT_NONCE.to_string()),
            storage: Default::default(),
        };

        self.genesis.alloc.insert(address, account);
        self.contracts_added += 1;

        info!("Added {} @ {}", name, config.address);

        Ok(())
    }
}

/// Parse address from hex string
fn parse_address(hex_str: &str) -> Result<Address> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let padded = if hex_str.len() < 40 { format!("{:0>40}", hex_str) } else { hex_str.to_string() };

    let bytes =
        hex::decode(&padded).map_err(|_| BuilderError::InvalidAddress(hex_str.to_string()))?;

    if bytes.len() != 20 {
        return Err(BuilderError::InvalidAddress(hex_str.to_string()));
    }

    Ok(Address::from_slice(&bytes))
}
