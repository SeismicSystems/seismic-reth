use reth_chainspec::ChainSpec;
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_seismic_chainspec::{
    check_genesis_extra_data, SEISMIC_DEV, SEISMIC_MAINNET, SEISMIC_TESTNET,
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

/// Clap value parser for Seismic [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
///
/// A genesis file must follow the Seismic `extraData` layout (a two-byte `timestampMillisPart`
/// prefix); a stock Ethereum genesis is rejected here rather than producing a chain whose head
/// cannot be built on.
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(match s {
        "dev" => SEISMIC_DEV.clone(),
        "testnet" => SEISMIC_TESTNET.clone(),
        "mainnet" => SEISMIC_MAINNET.clone(),
        _ => {
            let spec = ChainSpec::from_genesis(parse_genesis(s)?);
            check_genesis_extra_data(&spec).map_err(|err| {
                eyre::eyre!(
                    "genesis extraData must start with the 2-byte timestampMillisPart prefix \
                     (e.g. \"0x0000\"): {err}"
                )
            })?;
            Arc::new(spec)
        }
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

    #[test]
    fn genesis_files_need_the_timestamp_prefix() {
        let mut genesis = SEISMIC_DEV.genesis.clone();
        assert!(chain_value_parser(&serde_json::to_string(&genesis).unwrap()).is_ok());

        genesis.extra_data = Default::default();
        let error = chain_value_parser(&serde_json::to_string(&genesis).unwrap()).unwrap_err();
        assert!(error.to_string().contains("timestampMillisPart prefix"), "{error}");
    }
}
