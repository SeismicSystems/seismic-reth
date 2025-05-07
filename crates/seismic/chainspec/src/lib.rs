//! Seismic-Reth chain specs.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use std::sync::Arc;

use alloc::{boxed::Box, vec, vec::Vec};
use alloy_chains::Chain;
use alloy_consensus::{
    constants::{DEV_GENESIS_HASH, MAINNET_GENESIS_HASH},
    proofs::storage_root_unhashed,
    Header,
};
use alloy_eips::{eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS, eip7840::BlobParams};
use alloy_primitives::{b256, B256, U256};
use reth_chainspec::{
    make_genesis_header, BaseFeeParams, BaseFeeParamsKind, ChainSpec, ChainSpecBuilder,
    DepositContract, DisplayHardforks, EthChainSpec, EthereumHardforks, ForkFilter, ForkId,
    HardforkBlobParams, Hardforks, Head, DEV_HARDFORKS, MAINNET_PRUNE_DELETE_LIMIT,
};
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition};
use reth_primitives_traits::{sync::LazyLock, SealedHeader};

/// Seismic testnet specification
pub static SEISMIC_DEV: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("../res/genesis/dev.json"))
        .expect("Can't deserialize Dev testnet genesis json");
    let hardforks = DEV_HARDFORKS.clone();
    ChainSpec {
        chain: Chain::from_id(5124),
        genesis_header: SealedHeader::new(
            make_genesis_header(&genesis, &hardforks),
            DEV_GENESIS_HASH,
        ),
        genesis,
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks: DEV_HARDFORKS.clone(),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        deposit_contract: None, // TODO: do we even have?
        ..Default::default()
    }
    .into()
});

/// Seismic mainnet specification
pub static SEISMIC_MAINNET: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("../res/genesis/mainnet.json"))
        .expect("Can't deserialize Mainnet genesis json");
    let hardforks = EthereumHardfork::mainnet().into();
    let mut spec = ChainSpec {
        chain: Chain::from_id(5123),
        genesis_header: SealedHeader::new(
            make_genesis_header(&genesis, &hardforks),
            MAINNET_GENESIS_HASH,
        ),
        genesis,
        // <https://etherscan.io/block/15537394>
        paris_block_and_final_difficulty: Some((
            15537394,
            U256::from(58_750_003_716_598_352_816_469u128),
        )),
        hardforks,
        // https://etherscan.io/tx/0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0
        deposit_contract: Some(DepositContract::new(
            MAINNET_DEPOSIT_CONTRACT_ADDRESS,
            11052984,
            b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
        )),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        prune_delete_limit: MAINNET_PRUNE_DELETE_LIMIT,
        blob_params: HardforkBlobParams::default(),
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
    use alloy_genesis::{ChainConfig, Genesis};
    use alloy_primitives::b256;
    use reth_chainspec::{test_fork_ids, BaseFeeParams, BaseFeeParamsKind};
    use reth_ethereum_forks::{EthereumHardfork, ForkCondition, ForkHash, ForkId, Head};
    // use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition};

    use crate::*;

    #[test]
    fn base_mainnet_forkids() {
        let seismic_mainnet = &SEISMIC_MAINNET;
        test_fork_ids(
            &SEISMIC_MAINNET,
            &[
                (
                    Head { number: 0, ..Default::default() },
                    ForkId { hash: ForkHash([0x67, 0xda, 0x02, 0x60]), next: 1704992401 },
                ),
                (
                    Head { number: 0, timestamp: 1704992400, ..Default::default() },
                    ForkId { hash: ForkHash([0x67, 0xda, 0x02, 0x60]), next: 1704992401 },
                ),
                (
                    Head { number: 0, timestamp: 1704992401, ..Default::default() },
                    ForkId { hash: ForkHash([0x3c, 0x28, 0x3c, 0xb3]), next: 1710374401 },
                ),
                (
                    Head { number: 0, timestamp: 1710374400, ..Default::default() },
                    ForkId { hash: ForkHash([0x3c, 0x28, 0x3c, 0xb3]), next: 1710374401 },
                ),
                (
                    Head { number: 0, timestamp: 1710374401, ..Default::default() },
                    ForkId { hash: ForkHash([0x51, 0xcc, 0x98, 0xb3]), next: 1720627201 },
                ),
                (
                    Head { number: 0, timestamp: 1720627200, ..Default::default() },
                    ForkId { hash: ForkHash([0x51, 0xcc, 0x98, 0xb3]), next: 1720627201 },
                ),
                (
                    Head { number: 0, timestamp: 1720627201, ..Default::default() },
                    ForkId { hash: ForkHash([0xe4, 0x01, 0x0e, 0xb9]), next: 1726070401 },
                ),
                (
                    Head { number: 0, timestamp: 1726070401, ..Default::default() },
                    ForkId { hash: ForkHash([0xbc, 0x38, 0xf9, 0xca]), next: 1736445601 },
                ),
                (
                    Head { number: 0, timestamp: 1736445601, ..Default::default() },
                    ForkId { hash: ForkHash([0x3a, 0x2a, 0xf1, 0x83]), next: 0 },
                ),
            ],
        );
    }

    #[test]
    fn base_mainnet_genesis() {
        let genesis = SEISMIC_MAINNET.genesis_header();
        assert_eq!(
            genesis.hash_slow(),
            b256!("0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd")
        );
        let base_fee = genesis
            .next_block_base_fee(SEISMIC_MAINNET.base_fee_params_at_timestamp(genesis.timestamp))
            .unwrap();
        // <https://base.blockscout.com/block/1>
        assert_eq!(base_fee, 980000000);
    }

    #[test]
    fn latest_base_mainnet_fork_id() {
        assert_eq!(
            ForkId { hash: ForkHash([0x3a, 0x2a, 0xf1, 0x83]), next: 0 },
            SEISMIC_MAINNET.latest_fork_id()
        )
    }

    #[test]
    fn latest_base_mainnet_fork_id_with_builder() {
        let base_mainnet = &SEISMIC_MAINNET;
        assert_eq!(
            ForkId { hash: ForkHash([0x3a, 0x2a, 0xf1, 0x83]), next: 0 },
            base_mainnet.latest_fork_id()
        )
    }

    #[test]
    fn display_hardorks() {
        let content = SEISMIC_MAINNET.display_hardforks().to_string();
        for eth_hf in EthereumHardfork::VARIANTS {
            assert!(!content.contains(eth_hf.name()));
        }
    }
}
