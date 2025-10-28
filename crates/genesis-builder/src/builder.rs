use crate::{
    artifact::ArtifactLoader,
    error::{BuilderError, Result},
    types::{Genesis, GenesisAccount, Manifest},
};
use alloy_primitives::{hex, Address};

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
        println!(
            "Building genesis with {} contracts from {}",
            self.manifest.contracts.len(),
            self.manifest.metadata.base_url()
        );

        for (name, config) in &self.manifest.contracts.clone() {
            self.add_contract(name, config)?;
        }

        println!("Added {} contracts to genesis", self.contracts_added);
        Ok(self.genesis)
    }

    /// Add a single contract to genesis
    fn add_contract(&mut self, name: &str, config: &crate::types::ContractConfig) -> Result<()> {
        // Construct full URL from base + relative path
        let url = format!(
            "{}/{}",
            self.manifest.metadata.base_url().trim_end_matches('/'),
            config.artifact.trim_start_matches('/')
        );

        // Load artifact from URL using the loader
        let artifact = self.loader.load_artifact(&url)?;

        // Parse address
        let address = parse_address(&config.address)?;

        // Check for collision
        if self.genesis.alloc.contains_key(&address) {
            return Err(BuilderError::AddressCollision(format!("{} ({})", name, config.address)));
        }

        // Create account entry
        let account = GenesisAccount {
            code: Some(format!("0x{}", hex::encode(&artifact.bytecode))),
            balance: "0x0".to_string(),
            nonce: "0x1".to_string(),
            storage: Default::default(),
        };

        // Insert into genesis
        self.genesis.alloc.insert(address, account);
        self.contracts_added += 1;

        println!("Added {} @ {}", name, config.address);

        Ok(())
    }
}

/// Parse address from hex string
fn parse_address(hex_str: &str) -> Result<Address> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Pad to 40 chars if needed (20 bytes = 40 hex chars)
    let padded = if hex_str.len() < 40 { format!("{:0>40}", hex_str) } else { hex_str.to_string() };

    // Decode hex to bytes
    let bytes =
        hex::decode(&padded).map_err(|_| BuilderError::InvalidAddress(hex_str.to_string()))?;

    // Verify it's exactly 20 bytes
    if bytes.len() != 20 {
        return Err(BuilderError::InvalidAddress(hex_str.to_string()));
    }

    Ok(Address::from_slice(&bytes))
}
