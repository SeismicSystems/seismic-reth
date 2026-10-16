//! Seismic beacon consensus.
//!
//! Wraps [`EthBeaconConsensus`] and
//!
//! - enforces the Seismic `extra_data` layout on every header (a two-byte `timestampMillisPart`
//!   prefix, see [`reth_seismic_primitives::header`]), and
//! - relaxes the parent-timestamp rule to millisecond precision: Seismic produces sub-second
//!   blocks, so consecutive headers may share the same seconds `timestamp` as long as their
//!   millisecond block time strictly increases.

use alloy_consensus::{BlockHeader, Header};
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_eip1559_base_fee,
    validate_against_parent_gas_limit, validate_against_parent_hash_number,
};
use reth_execution_types::BlockExecutionResult;
use reth_node_ethereum::consensus::EthBeaconConsensus;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_seismic_primitives::{
    header::join_timestamp_millis, SeismicBlock, SeismicBlockBody, SeismicBlockHeader,
    SeismicPrimitives,
};
use std::sync::Arc;

/// Seismic consensus implementation.
#[derive(Debug, Clone)]
pub struct SeismicConsensus {
    inner: EthBeaconConsensus<ChainSpec>,
}

impl SeismicConsensus {
    /// Creates a new consensus for the given chain spec.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthBeaconConsensus::new(chain_spec) }
    }
}

/// Validates the header's `extra_data` layout and returns its block time as
/// `(seconds, millis_part)`.
///
/// Rejects `extra_data` shorter than the timestamp prefix or longer than the consensus maximum,
/// and a sub-second component outside `0..1000`.
pub fn validate_timestamp_millis(header: &Header) -> Result<(u64, u64), ConsensusError> {
    header
        .try_timestamp_millis_part()
        .map(|part| (header.timestamp(), part))
        .map_err(|err| ConsensusError::Other(err.to_string()))
}

/// Validates the millisecond ordering against the parent.
///
/// Both headers must follow the Seismic `extra_data` layout. The comparison is on the
/// `(seconds, millis_part)` pair, so no arithmetic (and no saturation) is involved.
pub fn validate_against_parent_timestamp_millis(
    header: &Header,
    parent: &Header,
) -> Result<(), ConsensusError> {
    let timestamp = validate_timestamp_millis(header)?;
    let parent_timestamp = validate_timestamp_millis(parent)?;
    if timestamp <= parent_timestamp {
        return Err(ConsensusError::TimestampIsInPast {
            parent_timestamp: join_timestamp_millis(parent_timestamp.0, parent_timestamp.1),
            timestamp: join_timestamp_millis(timestamp.0, timestamp.1),
        })
    }
    Ok(())
}

impl HeaderValidator<Header> for SeismicConsensus {
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        validate_timestamp_millis(header.header())?;
        self.inner.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
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
        header: &SealedHeader<Header>,
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
    use alloy_primitives::{bytes, Bytes};
    use reth_seismic_chainspec::SEISMIC_DEV;
    use reth_seismic_primitives::header::{encode_extra_data, MAX_BUILDER_EXTRA_DATA_LEN};

    fn header(timestamp: u64, part: u64) -> Header {
        Header {
            timestamp,
            extra_data: encode_extra_data(part, b"seismic").unwrap(),
            ..Default::default()
        }
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
    }

    /// A header that passes the stock standalone checks, so only the Seismic rule decides.
    fn well_formed(extra_data: Bytes) -> SealedHeader<Header> {
        SealedHeader::seal_slow(Header {
            number: 1,
            timestamp: 10,
            gas_limit: 30_000_000,
            extra_data,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(Default::default()),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        })
    }

    /// Upstream parity: `validate_header_against_parent` is a hand copy of
    /// `EthBeaconConsensus::validate_header_against_parent` with only the timestamp rule
    /// swapped. Pairs with strictly increasing *seconds* timestamps (so upstream's seconds rule
    /// passes and does not short-circuit) must produce identical results for every other rule;
    /// a check added upstream that the copy misses fails this test.
    #[test]
    fn parent_validation_matches_upstream_except_for_the_timestamp_rule() {
        use alloy_consensus::EMPTY_ROOT_HASH;
        use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
        use reth_chainspec::EthChainSpec as _;

        let spec = SEISMIC_DEV.clone();
        let upstream = EthBeaconConsensus::new(spec.clone());
        let seismic = SeismicConsensus::new(spec.clone());

        let parent = SealedHeader::seal_slow(Header {
            number: 10,
            timestamp: 1_800_000_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            extra_data: encode_extra_data(500, b"p").unwrap(),
            base_fee_per_gas: Some(1_000_000_000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(Default::default()),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        });
        let timestamp = parent.timestamp() + 1;
        let valid = Header {
            parent_hash: parent.hash(),
            number: parent.number() + 1,
            timestamp,
            gas_limit: parent.gas_limit(),
            extra_data: encode_extra_data(0, b"c").unwrap(),
            base_fee_per_gas: parent
                .next_block_base_fee(spec.base_fee_params_at_timestamp(timestamp)),
            excess_blob_gas: parent
                .maybe_next_block_excess_blob_gas(spec.blob_params_at_timestamp(timestamp)),
            ..parent.header().clone()
        };

        let cases: Vec<(&str, Header)> = vec![
            ("valid", valid.clone()),
            ("parent hash", Header { parent_hash: Default::default(), ..valid.clone() }),
            ("number", Header { number: valid.number + 1, ..valid.clone() }),
            ("gas limit", Header { gas_limit: valid.gas_limit * 2, ..valid.clone() }),
            (
                "base fee",
                Header { base_fee_per_gas: valid.base_fee_per_gas.map(|f| f + 1), ..valid.clone() },
            ),
            (
                "excess blob gas",
                Header { excess_blob_gas: valid.excess_blob_gas.map(|g| g + 1), ..valid.clone() },
            ),
        ];
        for (name, header) in cases {
            let header = SealedHeader::seal_slow(header);
            let expected = HeaderValidator::<Header>::validate_header_against_parent(
                &upstream, &header, &parent,
            );
            let actual = seismic.validate_header_against_parent(&header, &parent);
            assert_eq!(actual, expected, "{name}");
            assert_eq!(expected.is_ok(), name == "valid", "{name}");
        }

        // The one intended divergence: same seconds, later milliseconds.
        let same_second = SealedHeader::seal_slow(Header {
            timestamp: parent.timestamp(),
            extra_data: encode_extra_data(501, b"c").unwrap(),
            base_fee_per_gas: parent
                .next_block_base_fee(spec.base_fee_params_at_timestamp(parent.timestamp())),
            excess_blob_gas: parent.maybe_next_block_excess_blob_gas(
                spec.blob_params_at_timestamp(parent.timestamp()),
            ),
            ..valid
        });
        assert!(matches!(
            HeaderValidator::<Header>::validate_header_against_parent(
                &upstream,
                &same_second,
                &parent
            ),
            Err(ConsensusError::TimestampIsInPast { .. })
        ));
        assert_eq!(seismic.validate_header_against_parent(&same_second, &parent), Ok(()));
    }

    #[test]
    fn standalone_validation_enforces_the_extra_data_layout() {
        let consensus = SeismicConsensus::new(SEISMIC_DEV.clone());

        for extra_data in [
            encode_extra_data(0, b"").unwrap(),
            encode_extra_data(999, &[0xaa; MAX_BUILDER_EXTRA_DATA_LEN]).unwrap(),
        ] {
            assert_eq!(consensus.validate_header(&well_formed(extra_data)), Ok(()));
        }

        for (extra_data, expected) in [
            (Bytes::new(), "extraData is 0 bytes"),
            (bytes!("00"), "extraData is 1 bytes"),
            (bytes!("03e8"), "timestampMillisPart 1000 is out of range"),
            (Bytes::copy_from_slice(b"reth/v1.0.0/linux"), "timestampMillisPart 29285"),
            (Bytes::from(vec![0u8; 33]), "extraData is 33 bytes"),
        ] {
            let error = consensus.validate_header(&well_formed(extra_data)).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }
}
