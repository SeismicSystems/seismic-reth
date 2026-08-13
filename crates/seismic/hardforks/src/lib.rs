//! Seismic-Reth hard forks.
extern crate alloc;

use alloc::vec;
use alloy_primitives::uint;
use once_cell::sync::Lazy as LazyLock;
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition, Hardfork};

/// Seismic hardfork enum
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum SeismicHardfork {
    Mercury,
    Venus,
}

impl Hardfork for SeismicHardfork {
    fn name(&self) -> &'static str {
        match self {
            Self::Mercury => "Mercury",
            Self::Venus => "Venus",
        }
    }
}

/// Activation block for the [`SeismicHardfork::Venus`] hardfork, on every Seismic network.
///
/// Venus is an irregular state transition that force-replaces the bytecode of the USDC contract
/// with an updated version at this block. It is scheduled by block number (not timestamp) so the
/// block executor can detect the exact activation boundary from the block number alone and apply
/// the swap exactly once, with no per-block state access afterwards. See the Venus executor in
/// `reth-seismic-evm`.
///
/// The executor keys the swap off this constant directly (not off the chainspec fork schedule), so
/// it fires at this block regardless of how the chain was launched — including from a genesis JSON
/// file, which bypasses the built-in Seismic fork schedule. The schedule entries below exist so the
/// fork also participates in fork-id / p2p partitioning for nodes launched from the built-in specs.
pub const SEISMIC_VENUS_BLOCK: u64 = 39_307_813;

/// Builds the hardfork schedule shared by all Seismic networks.
fn seismic_hardforks() -> ChainHardforks {
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
        (SeismicHardfork::Mercury.boxed(), ForkCondition::Timestamp(0)),
        (SeismicHardfork::Venus.boxed(), ForkCondition::Block(SEISMIC_VENUS_BLOCK)),
    ])
}

/// Mainnet hardforks.
pub static SEISMIC_MAINNET_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(seismic_hardforks);

/// Public testnet hardforks.
pub static SEISMIC_TESTNET_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(seismic_hardforks);

/// Dev hardforks.
pub static SEISMIC_DEV_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(seismic_hardforks);

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use core::panic;

    fn assert_hardforks_at_zero(seismic_hardforks: &ChainHardforks) {
        let eth_mainnet_forks = EthereumHardfork::mainnet();
        for eth_hf in eth_mainnet_forks {
            let (fork, _) = eth_hf;
            let lookup = seismic_hardforks.get(fork);
            match lookup {
                Some(condition) => {
                    if fork <= EthereumHardfork::Prague {
                        assert!(
                            condition.active_at_timestamp(0) || condition.active_at_block(0),
                            "Hardfork {} not active at timestamp 1",
                            fork
                        );
                    }
                }
                None => {
                    panic!("Hardfork {} not found in hardforks", fork);
                }
            }
        }

        assert!(
            seismic_hardforks.get(SeismicHardfork::Mercury).is_some(),
            "Missing hardfork mercury"
        );
    }

    #[test]
    fn check_network_hardforks_at_zero() {
        assert_hardforks_at_zero(&SEISMIC_MAINNET_HARDFORKS);
        assert_hardforks_at_zero(&SEISMIC_TESTNET_HARDFORKS);
        assert_hardforks_at_zero(&SEISMIC_DEV_HARDFORKS);
    }

    #[test]
    fn venus_is_scheduled_on_all_networks() {
        let expected = Some(ForkCondition::Block(SEISMIC_VENUS_BLOCK));
        assert_eq!(SEISMIC_MAINNET_HARDFORKS.get(SeismicHardfork::Venus), expected);
        assert_eq!(SEISMIC_TESTNET_HARDFORKS.get(SeismicHardfork::Venus), expected);
        assert_eq!(SEISMIC_DEV_HARDFORKS.get(SeismicHardfork::Venus), expected);
    }

    #[test]
    fn venus_transitions_only_at_activation_block() {
        let venus = SEISMIC_MAINNET_HARDFORKS.fork(SeismicHardfork::Venus);
        assert!(venus.transitions_at_block(SEISMIC_VENUS_BLOCK));
        assert!(!venus.transitions_at_block(SEISMIC_VENUS_BLOCK - 1));
        assert!(!venus.transitions_at_block(SEISMIC_VENUS_BLOCK + 1));
    }
}
