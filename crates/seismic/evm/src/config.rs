use alloy_consensus::BlockHeader;
use seismic_revm::SeismicSpecId;
use reth_seismic_forks::SeismicHardfork;
use revm::primitives::{Address, Bytes, B256};
use reth_seismic_chainspec::{SeismicChainSpec};

/// Map the latest active hardfork at the given header to a revm [`SeismicSpecId`].
pub fn revm_spec(chain_spec: impl SeismicHardfork, header: impl BlockHeader) -> OpSpecId {
    revm_spec_by_timestamp_seismic(&chain_spec, header.timestamp())
}

/// Map the latest active hardfork at the given timestamp or block number to a revm [`SeismicSpecId`].
/// 
/// For now our only hardfork is MERCURY, so we only return MERCURY
fn revm_spec_by_timestamp_seismic(
    chain_spec: &SeismicChainSpec,
    timestamp: u64,
) -> SeismicSpecId {
        SeismicSpecId::MERCURY
}