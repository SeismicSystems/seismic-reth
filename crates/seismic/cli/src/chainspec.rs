use reth_chainspec::ChainSpec;
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_seismic_chainspec::{SEISMIC_DEV, SEISMIC_DEV_OLD, SEISMIC_MAINNET};
use std::sync::Arc;

/// Optimism chain specification parser.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SeismicChainSpecParser;

impl ChainSpecParser for SeismicChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &["dev", "mainnet", "dev-old"];

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
        "mainnet" => SEISMIC_MAINNET.clone(),
        "dev-old" => SEISMIC_DEV_OLD.clone(),
        _ => Arc::new(parse_genesis(s)?.into()),
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
