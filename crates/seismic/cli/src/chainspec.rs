use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_seismic_chainspec::{SeismicChainSpec, SEISMIC_DEV, SEISMIC_MAINNET, SEISMIC_TESTNET};
use std::sync::Arc;

/// Seismic chain specification parser.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SeismicChainSpecParser;

impl ChainSpecParser for SeismicChainSpecParser {
    type ChainSpec = SeismicChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &["dev", "testnet", "mainnet"];

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        chain_value_parser(s)
    }
}

/// Clap value parser for [`SeismicChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<SeismicChainSpec>, eyre::Error> {
    Ok(match s {
        "dev" => SEISMIC_DEV.clone(),
        "testnet" => SEISMIC_TESTNET.clone(),
        "mainnet" => SEISMIC_MAINNET.clone(),
        _ => Arc::new(SeismicChainSpec::from_genesis(parse_genesis(s)?)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_chain_spec() {
        for &chain in SeismicChainSpecParser::SUPPORTED_CHAINS {
            assert!(<SeismicChainSpecParser as ChainSpecParser>::parse(chain).is_ok());
        }
    }
}
