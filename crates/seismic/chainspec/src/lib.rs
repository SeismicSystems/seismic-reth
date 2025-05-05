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
use alloy_genesis::Genesis;
use alloy_hardforks::Hardfork;
use alloy_primitives::{b256, B256, U256};
use derive_more::{Constructor, Deref, From, Into};
use reth_chainspec::{
    make_genesis_header, BaseFeeParams, BaseFeeParamsKind, ChainSpec, ChainSpecBuilder,
    DepositContract, DisplayHardforks, EthChainSpec, EthereumHardforks, ForkFilter, ForkId,
    HardforkBlobParams, Hardforks, Head, DEV_HARDFORKS, MAINNET_PRUNE_DELETE_LIMIT,
};
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition};
use reth_network_peers::NodeRecord;
use reth_primitives_traits::{sync::LazyLock, SealedHeader};
use reth_seismic_primitives::ADDRESS_L2_TO_L1_MESSAGE_PASSER;

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

pub fn is_chain_seismic(chain: &Chain) -> bool {
    chain.id() == SEISMIC_MAINNET.chain.id() || chain.id() == SEISMIC_DEV.chain.id()
}

#[cfg(test)]
mod tests {
    use alloy_genesis::{ChainConfig, Genesis};
    use alloy_primitives::b256;
    use reth_chainspec::{test_fork_ids, BaseFeeParams, BaseFeeParamsKind};
    use reth_ethereum_forks::{EthereumHardfork, ForkCondition, ForkHash, ForkId, Head};
    use reth_seismic_hardforks::{OpHardfork, OpHardforks};

    use crate::*;

    #[test]
    fn base_mainnet_forkids() {
        let mut base_mainnet = ChainSpecBuilder::base_mainnet().build();
        base_mainnet.inner.genesis_header.set_hash(BASE_MAINNET.genesis_hash());
        test_fork_ids(
            &BASE_MAINNET,
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
    fn op_mainnet_forkids() {
        let mut op_mainnet = ChainSpecBuilder::optimism_mainnet().build();
        // for OP mainnet we have to do this because the genesis header can't be properly computed
        // from the genesis.json file
        op_mainnet.inner.genesis_header.set_hash(SEISMIC_MAINNET.genesis_hash());
        test_fork_ids(
            &op_mainnet,
            &[
                (
                    Head { number: 0, ..Default::default() },
                    ForkId { hash: ForkHash([0xca, 0xf5, 0x17, 0xed]), next: 3950000 },
                ),
                // London
                (
                    Head { number: 105235063, ..Default::default() },
                    ForkId { hash: ForkHash([0xe3, 0x39, 0x8d, 0x7c]), next: 1704992401 },
                ),
                // Bedrock
                (
                    Head { number: 105235063, ..Default::default() },
                    ForkId { hash: ForkHash([0xe3, 0x39, 0x8d, 0x7c]), next: 1704992401 },
                ),
                // Shanghai
                (
                    Head { number: 105235063, timestamp: 1704992401, ..Default::default() },
                    ForkId { hash: ForkHash([0xbd, 0xd4, 0xfd, 0xb2]), next: 1710374401 },
                ),
                // OP activation timestamps
                // https://specs.optimism.io/protocol/superchain-upgrades.html#activation-timestamps
                // Canyon
                (
                    Head { number: 105235063, timestamp: 1704992401, ..Default::default() },
                    ForkId { hash: ForkHash([0xbd, 0xd4, 0xfd, 0xb2]), next: 1710374401 },
                ),
                // Ecotone
                (
                    Head { number: 105235063, timestamp: 1710374401, ..Default::default() },
                    ForkId { hash: ForkHash([0x19, 0xda, 0x4c, 0x52]), next: 1720627201 },
                ),
                // Fjord
                (
                    Head { number: 105235063, timestamp: 1720627201, ..Default::default() },
                    ForkId { hash: ForkHash([0x49, 0xfb, 0xfe, 0x1e]), next: 1726070401 },
                ),
                // Granite
                (
                    Head { number: 105235063, timestamp: 1726070401, ..Default::default() },
                    ForkId { hash: ForkHash([0x44, 0x70, 0x4c, 0xde]), next: 1736445601 },
                ),
                // Holocene
                (
                    Head { number: 105235063, timestamp: 1736445601, ..Default::default() },
                    ForkId { hash: ForkHash([0x2b, 0xd9, 0x3d, 0xc8]), next: 0 },
                ),
            ],
        );
    }

    #[test]
    fn base_sepolia_forkids() {
        test_fork_ids(
            &BASE_SEPOLIA,
            &[
                (
                    Head { number: 0, ..Default::default() },
                    ForkId { hash: ForkHash([0xb9, 0x59, 0xb9, 0xf7]), next: 1699981200 },
                ),
                (
                    Head { number: 0, timestamp: 1699981199, ..Default::default() },
                    ForkId { hash: ForkHash([0xb9, 0x59, 0xb9, 0xf7]), next: 1699981200 },
                ),
                (
                    Head { number: 0, timestamp: 1699981200, ..Default::default() },
                    ForkId { hash: ForkHash([0x60, 0x7c, 0xd5, 0xa1]), next: 1708534800 },
                ),
                (
                    Head { number: 0, timestamp: 1708534799, ..Default::default() },
                    ForkId { hash: ForkHash([0x60, 0x7c, 0xd5, 0xa1]), next: 1708534800 },
                ),
                (
                    Head { number: 0, timestamp: 1708534800, ..Default::default() },
                    ForkId { hash: ForkHash([0xbe, 0x96, 0x9b, 0x17]), next: 1716998400 },
                ),
                (
                    Head { number: 0, timestamp: 1716998399, ..Default::default() },
                    ForkId { hash: ForkHash([0xbe, 0x96, 0x9b, 0x17]), next: 1716998400 },
                ),
                (
                    Head { number: 0, timestamp: 1716998400, ..Default::default() },
                    ForkId { hash: ForkHash([0x4e, 0x45, 0x7a, 0x49]), next: 1723478400 },
                ),
                (
                    Head { number: 0, timestamp: 1723478399, ..Default::default() },
                    ForkId { hash: ForkHash([0x4e, 0x45, 0x7a, 0x49]), next: 1723478400 },
                ),
                (
                    Head { number: 0, timestamp: 1723478400, ..Default::default() },
                    ForkId { hash: ForkHash([0x5e, 0xdf, 0xa3, 0xb6]), next: 1732633200 },
                ),
                (
                    Head { number: 0, timestamp: 1732633200, ..Default::default() },
                    ForkId { hash: ForkHash([0x8b, 0x5e, 0x76, 0x29]), next: 0 },
                ),
            ],
        );
    }

    #[test]
    fn base_mainnet_genesis() {
        let genesis = BASE_MAINNET.genesis_header();
        assert_eq!(
            genesis.hash_slow(),
            b256!("0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd")
        );
        let base_fee = genesis
            .next_block_base_fee(BASE_MAINNET.base_fee_params_at_timestamp(genesis.timestamp))
            .unwrap();
        // <https://base.blockscout.com/block/1>
        assert_eq!(base_fee, 980000000);
    }

    #[test]
    fn base_sepolia_genesis() {
        let genesis = BASE_SEPOLIA.genesis_header();
        assert_eq!(
            genesis.hash_slow(),
            b256!("0x0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4")
        );
        let base_fee = genesis
            .next_block_base_fee(BASE_SEPOLIA.base_fee_params_at_timestamp(genesis.timestamp))
            .unwrap();
        // <https://base-sepolia.blockscout.com/block/1>
        assert_eq!(base_fee, 980000000);
    }

    #[test]
    fn latest_base_mainnet_fork_id() {
        assert_eq!(
            ForkId { hash: ForkHash([0x3a, 0x2a, 0xf1, 0x83]), next: 0 },
            BASE_MAINNET.latest_fork_id()
        )
    }

    #[test]
    fn latest_base_mainnet_fork_id_with_builder() {
        let base_mainnet = ChainSpecBuilder::base_mainnet().build();
        assert_eq!(
            ForkId { hash: ForkHash([0x3a, 0x2a, 0xf1, 0x83]), next: 0 },
            base_mainnet.latest_fork_id()
        )
    }

    #[test]
    fn is_bedrock_active() {
        let op_mainnet = ChainSpecBuilder::optimism_mainnet().build();
        assert!(!op_mainnet.is_bedrock_active_at_block(1))
    }

    #[test]
    fn parse_optimism_hardforks() {
        let geth_genesis = r#"
    {
      "config": {
        "bedrockBlock": 10,
        "regolithTime": 20,
        "canyonTime": 30,
        "ecotoneTime": 40,
        "fjordTime": 50,
        "graniteTime": 51,
        "holoceneTime": 52,
        "optimism": {
          "eip1559Elasticity": 60,
          "eip1559Denominator": 70
        }
      }
    }
    "#;
        let genesis: Genesis = serde_json::from_str(geth_genesis).unwrap();

        let actual_bedrock_block = genesis.config.extra_fields.get("bedrockBlock");
        assert_eq!(actual_bedrock_block, Some(serde_json::Value::from(10)).as_ref());
        let actual_regolith_timestamp = genesis.config.extra_fields.get("regolithTime");
        assert_eq!(actual_regolith_timestamp, Some(serde_json::Value::from(20)).as_ref());
        let actual_canyon_timestamp = genesis.config.extra_fields.get("canyonTime");
        assert_eq!(actual_canyon_timestamp, Some(serde_json::Value::from(30)).as_ref());
        let actual_ecotone_timestamp = genesis.config.extra_fields.get("ecotoneTime");
        assert_eq!(actual_ecotone_timestamp, Some(serde_json::Value::from(40)).as_ref());
        let actual_fjord_timestamp = genesis.config.extra_fields.get("fjordTime");
        assert_eq!(actual_fjord_timestamp, Some(serde_json::Value::from(50)).as_ref());
        let actual_granite_timestamp = genesis.config.extra_fields.get("graniteTime");
        assert_eq!(actual_granite_timestamp, Some(serde_json::Value::from(51)).as_ref());
        let actual_holocene_timestamp = genesis.config.extra_fields.get("holoceneTime");
        assert_eq!(actual_holocene_timestamp, Some(serde_json::Value::from(52)).as_ref());

        let optimism_object = genesis.config.extra_fields.get("optimism").unwrap();
        assert_eq!(
            optimism_object,
            &serde_json::json!({
                "eip1559Elasticity": 60,
                "eip1559Denominator": 70,
            })
        );

        let chain_spec: ChainSpec = genesis.into();

        assert_eq!(
            chain_spec.base_fee_params,
            BaseFeeParamsKind::Constant(BaseFeeParams::new(70, 60))
        );

        assert!(!chain_spec.is_fork_active_at_block(OpHardfork::Bedrock, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Regolith, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Canyon, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Ecotone, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Fjord, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Granite, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Holocene, 0));

        assert!(chain_spec.is_fork_active_at_block(OpHardfork::Bedrock, 10));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Regolith, 20));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Canyon, 30));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Ecotone, 40));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Fjord, 50));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Granite, 51));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Holocene, 52));
    }

    #[test]
    fn parse_optimism_hardforks_variable_base_fee_params() {
        let geth_genesis = r#"
    {
      "config": {
        "bedrockBlock": 10,
        "regolithTime": 20,
        "canyonTime": 30,
        "ecotoneTime": 40,
        "fjordTime": 50,
        "graniteTime": 51,
        "holoceneTime": 52,
        "optimism": {
          "eip1559Elasticity": 60,
          "eip1559Denominator": 70,
          "eip1559DenominatorCanyon": 80
        }
      }
    }
    "#;
        let genesis: Genesis = serde_json::from_str(geth_genesis).unwrap();

        let actual_bedrock_block = genesis.config.extra_fields.get("bedrockBlock");
        assert_eq!(actual_bedrock_block, Some(serde_json::Value::from(10)).as_ref());
        let actual_regolith_timestamp = genesis.config.extra_fields.get("regolithTime");
        assert_eq!(actual_regolith_timestamp, Some(serde_json::Value::from(20)).as_ref());
        let actual_canyon_timestamp = genesis.config.extra_fields.get("canyonTime");
        assert_eq!(actual_canyon_timestamp, Some(serde_json::Value::from(30)).as_ref());
        let actual_ecotone_timestamp = genesis.config.extra_fields.get("ecotoneTime");
        assert_eq!(actual_ecotone_timestamp, Some(serde_json::Value::from(40)).as_ref());
        let actual_fjord_timestamp = genesis.config.extra_fields.get("fjordTime");
        assert_eq!(actual_fjord_timestamp, Some(serde_json::Value::from(50)).as_ref());
        let actual_granite_timestamp = genesis.config.extra_fields.get("graniteTime");
        assert_eq!(actual_granite_timestamp, Some(serde_json::Value::from(51)).as_ref());
        let actual_holocene_timestamp = genesis.config.extra_fields.get("holoceneTime");
        assert_eq!(actual_holocene_timestamp, Some(serde_json::Value::from(52)).as_ref());

        let optimism_object = genesis.config.extra_fields.get("optimism").unwrap();
        assert_eq!(
            optimism_object,
            &serde_json::json!({
                "eip1559Elasticity": 60,
                "eip1559Denominator": 70,
                "eip1559DenominatorCanyon": 80
            })
        );

        let chain_spec: ChainSpec = genesis.into();

        assert_eq!(
            chain_spec.base_fee_params,
            BaseFeeParamsKind::Variable(
                vec![
                    (EthereumHardfork::London.boxed(), BaseFeeParams::new(70, 60)),
                    (OpHardfork::Canyon.boxed(), BaseFeeParams::new(80, 60)),
                ]
                .into()
            )
        );

        assert!(!chain_spec.is_fork_active_at_block(OpHardfork::Bedrock, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Regolith, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Canyon, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Ecotone, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Fjord, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Granite, 0));
        assert!(!chain_spec.is_fork_active_at_timestamp(OpHardfork::Holocene, 0));

        assert!(chain_spec.is_fork_active_at_block(OpHardfork::Bedrock, 10));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Regolith, 20));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Canyon, 30));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Ecotone, 40));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Fjord, 50));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Granite, 51));
        assert!(chain_spec.is_fork_active_at_timestamp(OpHardfork::Holocene, 52));
    }

    #[test]
    fn parse_genesis_optimism_with_variable_base_fee_params() {
        use seismic_alloy_rpc_types::OpBaseFeeInfo;

        let geth_genesis = r#"
    {
      "config": {
        "chainId": 8453,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "arrowGlacierBlock": 0,
        "grayGlacierBlock": 0,
        "mergeNetsplitBlock": 0,
        "bedrockBlock": 0,
        "regolithTime": 15,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": true,
        "optimism": {
          "eip1559Elasticity": 6,
          "eip1559Denominator": 50
        }
      }
    }
    "#;
        let genesis: Genesis = serde_json::from_str(geth_genesis).unwrap();
        let chainspec = ChainSpec::from(genesis.clone());

        let actual_chain_id = genesis.config.chain_id;
        assert_eq!(actual_chain_id, 8453);

        assert_eq!(
            chainspec.hardforks.get(EthereumHardfork::Istanbul),
            Some(ForkCondition::Block(0))
        );

        let actual_bedrock_block = genesis.config.extra_fields.get("bedrockBlock");
        assert_eq!(actual_bedrock_block, Some(serde_json::Value::from(0)).as_ref());
        let actual_canyon_timestamp = genesis.config.extra_fields.get("canyonTime");
        assert_eq!(actual_canyon_timestamp, None);

        assert!(genesis.config.terminal_total_difficulty_passed);

        let optimism_object = genesis.config.extra_fields.get("optimism").unwrap();
        let optimism_base_fee_info =
            serde_json::from_value::<OpBaseFeeInfo>(optimism_object.clone()).unwrap();

        assert_eq!(
            optimism_base_fee_info,
            OpBaseFeeInfo {
                eip1559_elasticity: Some(6),
                eip1559_denominator: Some(50),
                eip1559_denominator_canyon: None,
            }
        );
        assert_eq!(
            chainspec.base_fee_params,
            BaseFeeParamsKind::Constant(BaseFeeParams {
                max_change_denominator: 50,
                elasticity_multiplier: 6,
            })
        );

        assert!(chainspec.is_fork_active_at_block(OpHardfork::Bedrock, 0));

        assert!(chainspec.is_fork_active_at_timestamp(OpHardfork::Regolith, 20));
    }

    #[test]
    fn test_fork_order_optimism_mainnet() {
        use reth_seismic_hardforks::OpHardfork;

        let genesis = Genesis {
            config: ChainConfig {
                chain_id: 0,
                homestead_block: Some(0),
                dao_fork_block: Some(0),
                dao_fork_support: false,
                eip150_block: Some(0),
                eip155_block: Some(0),
                eip158_block: Some(0),
                byzantium_block: Some(0),
                constantinople_block: Some(0),
                petersburg_block: Some(0),
                istanbul_block: Some(0),
                muir_glacier_block: Some(0),
                berlin_block: Some(0),
                london_block: Some(0),
                arrow_glacier_block: Some(0),
                gray_glacier_block: Some(0),
                merge_netsplit_block: Some(0),
                shanghai_time: Some(0),
                cancun_time: Some(0),
                terminal_total_difficulty: Some(U256::ZERO),
                extra_fields: [
                    (String::from("bedrockBlock"), 0.into()),
                    (String::from("regolithTime"), 0.into()),
                    (String::from("canyonTime"), 0.into()),
                    (String::from("ecotoneTime"), 0.into()),
                    (String::from("fjordTime"), 0.into()),
                    (String::from("graniteTime"), 0.into()),
                    (String::from("holoceneTime"), 0.into()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..Default::default()
        };

        let chain_spec: ChainSpec = genesis.into();

        let hardforks: Vec<_> = chain_spec.hardforks.forks_iter().map(|(h, _)| h).collect();
        let expected_hardforks = vec![
            EthereumHardfork::Frontier.boxed(),
            EthereumHardfork::Homestead.boxed(),
            EthereumHardfork::Tangerine.boxed(),
            EthereumHardfork::SpuriousDragon.boxed(),
            EthereumHardfork::Byzantium.boxed(),
            EthereumHardfork::Constantinople.boxed(),
            EthereumHardfork::Petersburg.boxed(),
            EthereumHardfork::Istanbul.boxed(),
            EthereumHardfork::MuirGlacier.boxed(),
            EthereumHardfork::Berlin.boxed(),
            EthereumHardfork::London.boxed(),
            EthereumHardfork::ArrowGlacier.boxed(),
            EthereumHardfork::GrayGlacier.boxed(),
            EthereumHardfork::Paris.boxed(),
            OpHardfork::Bedrock.boxed(),
            OpHardfork::Regolith.boxed(),
            EthereumHardfork::Shanghai.boxed(),
            OpHardfork::Canyon.boxed(),
            EthereumHardfork::Cancun.boxed(),
            OpHardfork::Ecotone.boxed(),
            OpHardfork::Fjord.boxed(),
            OpHardfork::Granite.boxed(),
            OpHardfork::Holocene.boxed(),
            // OpHardfork::Isthmus.boxed(),
            // OpHardfork::Interop.boxed(),
        ];

        for (expected, actual) in expected_hardforks.iter().zip(hardforks.iter()) {
            println!("got {expected:?}, {actual:?}");
            assert_eq!(&**expected, &**actual);
        }
        assert_eq!(expected_hardforks.len(), hardforks.len());
    }

    #[test]
    fn json_genesis() {
        let geth_genesis = r#"
{
    "config": {
        "chainId": 1301,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "arrowGlacierBlock": 0,
        "grayGlacierBlock": 0,
        "mergeNetsplitBlock": 0,
        "shanghaiTime": 0,
        "cancunTime": 0,
        "bedrockBlock": 0,
        "regolithTime": 0,
        "canyonTime": 0,
        "ecotoneTime": 0,
        "fjordTime": 0,
        "graniteTime": 0,
        "holoceneTime": 1732633200,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": true,
        "optimism": {
            "eip1559Elasticity": 6,
            "eip1559Denominator": 50,
            "eip1559DenominatorCanyon": 250
        }
    },
    "nonce": "0x0",
    "timestamp": "0x66edad4c",
    "extraData": "0x424544524f434b",
    "gasLimit": "0x1c9c380",
    "difficulty": "0x0",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x4200000000000000000000000000000000000011",
    "alloc": {},
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "baseFeePerGas": "0x3b9aca00",
    "excessBlobGas": "0x0",
    "blobGasUsed": "0x0"
}
        "#;

        let genesis: Genesis = serde_json::from_str(geth_genesis).unwrap();
        let chainspec = ChainSpec::from_genesis(genesis);
        assert!(chainspec.is_holocene_active_at_timestamp(1732633200));
    }

    #[test]
    fn display_hardorks() {
        let content = BASE_MAINNET.display_hardforks().to_string();
        for eth_hf in EthereumHardfork::VARIANTS {
            assert!(!content.contains(eth_hf.name()));
        }
    }
}
