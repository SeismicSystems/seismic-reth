//! Seismic-Reth hard forks.
extern crate alloc;

use alloc::vec;
use once_cell::sync::Lazy as LazyLock;
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition, Hardfork};
use alloy_primitives::uint;


/// Seismic hardfork enum
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum SeismicHardfork {
    MERCURY,
}

impl Hardfork for SeismicHardfork {
    fn name(&self) -> &'static str {
        match self {
            Self::MERCURY => "Mercury",
        }
    }
}

/// Mainnet hardforks
/// Based off EthereumHardfork::mainnet(), 
/// with existing eth hardforks activated at block 0
pub static SEISMIC_MAINNET_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::MuirGlacier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::ArrowGlacier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::GrayGlacier.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: None,
                total_difficulty: uint!(58_750_000_000_000_000_000_000_U256),
            },
        ),
        (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(0)),
        (SeismicHardfork::MERCURY.boxed(), ForkCondition::Timestamp(0)),
    ])
});

/// Dev hardforks
pub static SEISMIC_DEV_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::MuirGlacier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::ArrowGlacier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::GrayGlacier.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: None,
                total_difficulty: uint!(58_750_000_000_000_000_000_000_U256),
            },
        ),
        (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(0)),
        (SeismicHardfork::MERCURY.boxed(), ForkCondition::Timestamp(0)),
    ])
});

#[cfg(test)]
mod tests {
    use core::panic;
    use super::*;

    #[test]
    fn check_ethereum_hardforks_at_zero() {
        let eth_mainnet_forks = EthereumHardfork::mainnet();
        let seismic_hardforks = SEISMIC_MAINNET_HARDFORKS.clone();
        for eth_hf in eth_mainnet_forks {
            let (fork, _) = eth_hf;
            let lookup = seismic_hardforks.get(fork);
            match lookup {
                Some(condition) => {
                    if fork <= EthereumHardfork::Prague {
                        assert!(condition.active_at_timestamp(0) || condition.active_at_block(0), "Hardfork {} not active at timestamp 1", fork);
                    }
                }
                None => {
                    panic!("Hardfork {} not found in hardforks", fork);
                }
            }
        }
    }

    #[test]
    fn check_seismic_hardforks_at_zero() {
        let seismic_hardforks = SEISMIC_MAINNET_HARDFORKS.clone();
        assert!(seismic_hardforks.get(SeismicHardfork::MERCURY).is_some(), "Missing hardfork mercury");
    }
}