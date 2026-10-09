//! Seismic beacon consensus.
//!
//! Wraps [`EthBeaconConsensus`] and relaxes the parent-timestamp rule to millisecond precision:
//! Seismic produces sub-second blocks, so consecutive headers may share the same seconds
//! `timestamp` as long as their millisecond block time strictly increases.

use alloy_consensus::BlockHeader;
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_eip1559_base_fee,
    validate_against_parent_gas_limit, validate_against_parent_hash_number,
};
use reth_execution_types::BlockExecutionResult;
use reth_node_ethereum::consensus::EthBeaconConsensus;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_seismic_chainspec::SeismicChainSpec;
use reth_seismic_engine_types::MILLIS_PER_SECOND;
use reth_seismic_primitives::{SeismicBlock, SeismicBlockBody, SeismicHeader, SeismicPrimitives};
use std::sync::Arc;

/// Seismic consensus implementation.
#[derive(Debug, Clone)]
pub struct SeismicConsensus {
    inner: EthBeaconConsensus<SeismicChainSpec>,
}

impl SeismicConsensus {
    /// Creates a new consensus for the given chain spec.
    pub const fn new(chain_spec: Arc<SeismicChainSpec>) -> Self {
        Self { inner: EthBeaconConsensus::new(chain_spec) }
    }
}

/// Validates the sub-second timestamp component and the millisecond ordering against the parent.
pub fn validate_against_parent_timestamp_millis(
    header: &SeismicHeader,
    parent: &SeismicHeader,
) -> Result<(), ConsensusError> {
    if header.timestamp_millis_part >= MILLIS_PER_SECOND {
        return Err(ConsensusError::Other(format!(
            "timestampMillisPart {} is out of range (expected 0..{MILLIS_PER_SECOND})",
            header.timestamp_millis_part
        )))
    }
    if header.timestamp_millis() <= parent.timestamp_millis() {
        return Err(ConsensusError::TimestampIsInPast {
            parent_timestamp: parent.timestamp_millis(),
            timestamp: header.timestamp_millis(),
        })
    }
    Ok(())
}

impl HeaderValidator<SeismicHeader> for SeismicConsensus {
    fn validate_header(&self, header: &SealedHeader<SeismicHeader>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<SeismicHeader>,
        parent: &SealedHeader<SeismicHeader>,
    ) -> Result<(), ConsensusError> {
        let chain_spec = self.inner.chain_spec();
        validate_against_parent_hash_number(header.header(), parent)?;
        // Replaces the strict seconds-based rule of the Ethereum consensus; everything else
        // mirrors `EthBeaconConsensus::validate_header_against_parent`.
        validate_against_parent_timestamp_millis(header.header(), parent.header())?;
        validate_against_parent_gas_limit(header, parent, chain_spec.as_ref())?;
        validate_against_parent_eip1559_base_fee(
            header.header(),
            parent.header(),
            chain_spec.as_ref(),
        )?;
        if let Some(blob_params) = chain_spec.blob_params_at_timestamp(header.timestamp()) {
            validate_against_parent_4844(header.header(), parent.header(), blob_params)?;
        }
        Ok(())
    }
}

impl Consensus<SeismicBlock> for SeismicConsensus {
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        body: &SeismicBlockBody,
        header: &SealedHeader<SeismicHeader>,
    ) -> Result<(), Self::Error> {
        Consensus::<SeismicBlock>::validate_body_against_header(&self.inner, body, header)
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<SeismicBlock>,
    ) -> Result<(), Self::Error> {
        Consensus::<SeismicBlock>::validate_block_pre_execution(&self.inner, block)
    }
}

impl FullConsensus<SeismicPrimitives> for SeismicConsensus {
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<SeismicBlock>,
        result: &BlockExecutionResult<reth_seismic_primitives::SeismicReceipt>,
    ) -> Result<(), ConsensusError> {
        FullConsensus::<SeismicPrimitives>::validate_block_post_execution(
            &self.inner,
            block,
            result,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;

    fn header(timestamp: u64, part: u64) -> SeismicHeader {
        SeismicHeader::new(Header { timestamp, ..Default::default() }, part)
    }

    #[test]
    fn same_second_blocks_are_ordered_by_millis() {
        assert!(
            validate_against_parent_timestamp_millis(&header(10, 500), &header(10, 499)).is_ok()
        );
        assert!(validate_against_parent_timestamp_millis(&header(11, 0), &header(10, 999)).is_ok());
        assert!(
            validate_against_parent_timestamp_millis(&header(10, 500), &header(10, 500)).is_err()
        );
        assert!(validate_against_parent_timestamp_millis(&header(10, 0), &header(10, 1)).is_err());
        assert!(validate_against_parent_timestamp_millis(&header(9, 999), &header(10, 0)).is_err());
        assert!(
            validate_against_parent_timestamp_millis(&header(11, 1000), &header(10, 0)).is_err()
        );
    }
}
