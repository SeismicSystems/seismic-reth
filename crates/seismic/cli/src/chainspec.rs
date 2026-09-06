use reth_chainspec::ChainSpec;
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_seismic_chainspec::{
    seismic_chain_spec_from_genesis, SEISMIC_DEV, SEISMIC_MAINNET, SEISMIC_TESTNET,
};
use std::sync::Arc;

/// Seismic chain specification parser.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SeismicChainSpecParser;

impl ChainSpecParser for SeismicChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &["dev", "testnet", "mainnet"];

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        chain_value_parser(s)
    }
}

/// Clap value parser for [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(match s {
        "dev" => SEISMIC_DEV.clone(),
        "testnet" => SEISMIC_TESTNET.clone(),
        "mainnet" => SEISMIC_MAINNET.clone(),
        _ => Arc::new(seismic_chain_spec_from_genesis(parse_genesis(s)?)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::EthereumHardforks;

    #[test]
    fn parse_known_chain_spec() {
        for &chain in SeismicChainSpecParser::SUPPORTED_CHAINS {
            assert!(<SeismicChainSpecParser as ChainSpecParser>::parse(chain).is_ok());
        }
    }

    #[test]
    fn genesis_file_uses_canonical_seismic_spec() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../chainspec/res/genesis/dev.json");
        let parsed = chain_value_parser(path).unwrap();

        assert!(!SEISMIC_DEV.is_osaka_active_at_timestamp(0));
        assert!(!parsed.is_osaka_active_at_timestamp(0));
        assert_eq!(parsed.hardforks, SEISMIC_DEV.hardforks);
        assert_eq!(parsed.genesis_hash(), SEISMIC_DEV.genesis_hash());
        assert_eq!(parsed.genesis_timestamp(), SEISMIC_DEV.genesis_timestamp());
        assert_eq!(
            parsed.paris_block_and_final_difficulty,
            SEISMIC_DEV.paris_block_and_final_difficulty
        );
        assert_eq!(parsed.chain, SEISMIC_DEV.chain);
        assert_eq!(&parsed.genesis.alloc, &SEISMIC_DEV.genesis.alloc);
    }
}
