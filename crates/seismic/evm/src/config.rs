//! Helpers for configuring the `SeismicSpecId` for the evm

use alloy_consensus::BlockHeader;
use reth_chainspec::ChainSpec;
use seismic_revm::SeismicSpecId;

/// Map the latest active hardfork at the given header to a revm [`SeismicSpecId`].
pub fn revm_spec<H: BlockHeader>(chain_spec: &ChainSpec, header: &H) -> SeismicSpecId {
    revm_spec_by_timestamp_seismic(chain_spec, header.timestamp())
}

/// Map the latest active hardfork at the given timestamp or block number to a revm
/// [`SeismicSpecId`].
///
/// For now our only hardfork is MERCURY, so we only return MERCURY
const fn revm_spec_by_timestamp_seismic(_chain_spec: &ChainSpec, _timestamp: u64) -> SeismicSpecId {
    SeismicSpecId::MERCURY
}
