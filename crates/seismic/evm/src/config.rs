use alloy_consensus::BlockHeader;
use seismic_revm::SeismicSpecId;
use reth_seismic_forks::SeismicHardfork;
use revm::primitives::{Address, Bytes, B256};
use reth_seismic_chainspec::{SeismicChainSpec};

/// Map the latest active hardfork at the given header to a revm [`SeismicSpecId`].
pub fn revm_spec(chain_spec: impl SeismicHardfork, header: impl BlockHeader) -> OpSpecId {
    revm_spec_by_timestamp_after_bedrock(chain_spec, header.timestamp())
}

/// Map the latest active hardfork at the given timestamp or block number to a revm [`SeismicSpecId`].
pub fn revm_spec_by_timestamp_and_block_number(
    chain_spec: &SeismicChainSpec,
    timestamp: u64,
    block_number: u64,
) -> SpecId {
    if chain_spec
        .fork(SeismicHardfork::MERCURY)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SeismicSpecId::MERCURY
    } 
}