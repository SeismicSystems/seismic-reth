//! Seismic-Reth chain specs.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use std::sync::Arc;

use alloy_chains::Chain;
use alloy_primitives::{B256, U256, b256};
use reth_chainspec::{
    BaseFeeParams, BaseFeeParamsKind, ChainSpec, DEV_HARDFORKS, make_genesis_header,
};
use reth_primitives_traits::{SealedHeader, sync::LazyLock};
use reth_seismic_forks::{SEISMIC_DEV_HARDFORKS, SEISMIC_MAINNET_HARDFORKS};

/// Genesis hash for the Seismic mainnet
/// Calculated by rlp encoding the genesis header and hashing it
pub const SEISMIC_MAINNET_GENESIS_HASH: B256 =
    b256!("0xee01857dd54ff6d7de6a90b2a76b42a86b7ea8f3a6d2ae27bd45ee6b3698b7b2");

/// Genesis hash for the Seismic devnet
/// Calculated by rlp encoding the genesis header and hashing it
/// Currently matches the mainnet genesis hash because they have matching hardforks
pub const SEISMIC_DEV_GENESIS_HASH: B256 =
    b256!("0xee01857dd54ff6d7de6a90b2a76b42a86b7ea8f3a6d2ae27bd45ee6b3698b7b2");

/// Seismic testnet specification
pub static SEISMIC_DEV: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("../res/genesis/dev.json"))
        .expect("Can't deserialize Dev testnet genesis json");
    let hardforks = SEISMIC_DEV_HARDFORKS.clone();
    ChainSpec {
        chain: Chain::from_id(5124),
        genesis_header: SealedHeader::new(
            make_genesis_header(&genesis, &hardforks),
            SEISMIC_DEV_GENESIS_HASH,
        ),
        genesis,
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks: DEV_HARDFORKS.clone(),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        deposit_contract: None,
        ..Default::default()
    }
    .into()
});

/// Seismic Mainnet
pub static SEISMIC_MAINNET: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("../res/genesis/mainnet.json"))
        .expect("Can't deserialize Mainnet genesis json");
    let hardforks = SEISMIC_MAINNET_HARDFORKS.clone();
    let mut spec = ChainSpec {
        chain: Chain::from_id(5123),
        genesis_header: SealedHeader::new(
            make_genesis_header(&genesis, &hardforks),
            SEISMIC_MAINNET_GENESIS_HASH,
        ),
        genesis,
        // <https://etherscan.io/block/15537394>
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks,
        // https://etherscan.io/tx/0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0
        deposit_contract: None,
        ..Default::default()
    };
    spec.genesis.config.dao_fork_support = true;
    spec.into()
});

/// Returns `true` if the given chain is a seismic chain.
pub fn is_chain_seismic(chain: &Chain) -> bool {
    chain.id() == SEISMIC_MAINNET.chain.id() || chain.id() == SEISMIC_DEV.chain.id()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use alloy_consensus::constants::MAINNET_GENESIS_HASH;
    use reth_chainspec::MAINNET;
    use reth_ethereum_forks::EthereumHardfork;
    use reth_seismic_forks::SeismicHardfork;

    #[test]
    fn seismic_mainnet_genesis() {
        let genesis = SEISMIC_MAINNET.genesis_header();
        let eth_genesis = MAINNET.genesis_header();
        assert_ne!(
            genesis.hash_slow(),
            eth_genesis.hash_slow(),
            "Seismic spec should not match eth genesis"
        );
        assert_eq!(
            genesis.hash_slow(),
            SEISMIC_MAINNET_GENESIS_HASH,
            "Seismic spec has correct genesis hash"
        );
    }

    // Test that the latest fork id is the latest seismic fork (mercury)
    #[test]
    fn latest_seismic_mainnet_fork_id_with_builder() {
        let seismic_mainnet = &SEISMIC_MAINNET;
        assert_eq!(
            seismic_mainnet.hardfork_fork_id(SeismicHardfork::MERCURY).unwrap(),
            seismic_mainnet.latest_fork_id()
        )
    }

    // Check display contains all eth mainnet hardforks and the seismic mercury fork
    #[test]
    fn display_hardforks() {
        let content = SEISMIC_MAINNET.display_hardforks().to_string();
        let eth_mainnet = EthereumHardfork::mainnet();
        for (eth_hf, _) in eth_mainnet {
            assert!(content.contains(eth_hf.name()), "missing hardfork {eth_hf}");
        }
        assert!(content.contains("Mercury"));
    }

    #[test]
    fn genesis_header_hash() {
        // Confirm how mainnet genesis header hash is calculated
        let expected = MAINNET_GENESIS_HASH;
        let genesis = serde_json::from_str(include_str!("../res/genesis/mainnet.json"))
            .expect("Can't deserialize Mainnet genesis json");
        let hardforks = EthereumHardfork::mainnet().into();
        let genesis_header = make_genesis_header(&genesis, &hardforks);
        let actual_hash = genesis_header.hash_slow();
        assert_eq!(actual_hash, expected);

        // Confirm seismic mainnet genesis header hash is calculated correctly
        let expected = SEISMIC_MAINNET_GENESIS_HASH;
        let genesis = serde_json::from_str(include_str!("../res/genesis/mainnet.json"))
            .expect("Can't deserialize Mainnet genesis json");
        let hardforks = SEISMIC_MAINNET_HARDFORKS.clone();
        let genesis_header = make_genesis_header(&genesis, &hardforks);
        let actual_hash = genesis_header.hash_slow();
        assert_eq!(actual_hash, expected);

        // Confirm seismic devnet genesis header hash is calculated correctly
        let expected = SEISMIC_DEV_GENESIS_HASH;
        let genesis = serde_json::from_str(include_str!("../res/genesis/mainnet.json"))
            .expect("Can't deserialize Mainnet genesis json");
        let hardforks = SEISMIC_DEV_HARDFORKS.clone();
        let genesis_header = make_genesis_header(&genesis, &hardforks);
        let actual_hash = genesis_header.hash_slow();
        assert_eq!(actual_hash, expected);
    }
}
