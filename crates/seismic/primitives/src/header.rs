//! Seismic block header conventions.
//!
//! Seismic blocks use the stock Ethereum [`Header`](alloy_consensus::Header): `timestamp` keeps
//! its standard meaning (Unix **seconds**) and the block hash is the standard header hash, so
//! every upstream consumer and every Ethereum tool sees a normal header. The sub-second
//! (milliseconds) component of the block time is carried in the first two bytes of
//! `extra_data`; see [`reth_seismic_engine_types::extra_data`] for the layout.

use alloy_consensus::BlockHeader;
pub use reth_seismic_engine_types::{
    builder_extra_data, decode_timestamp_millis_part, encode_extra_data, header_timestamp_millis,
    join_timestamp_millis, split_timestamp_millis, timestamp_millis_part_or_zero, ExtraDataError,
    MAX_BUILDER_EXTRA_DATA_LEN, MILLIS_PER_SECOND, TIMESTAMP_MILLIS_PREFIX_LEN,
};

/// Millisecond block-time accessors for Seismic headers.
pub trait SeismicBlockHeader: BlockHeader {
    /// Validates the `extra_data` layout and returns the sub-second component (`0..1000`).
    fn try_timestamp_millis_part(&self) -> Result<u64, ExtraDataError> {
        decode_timestamp_millis_part(self.extra_data())
    }

    /// Validates the `extra_data` layout and returns the block time in Unix milliseconds.
    fn try_timestamp_millis(&self) -> Result<u64, ExtraDataError> {
        header_timestamp_millis(self.timestamp(), self.extra_data())
    }

    /// Returns the sub-second component, treating malformed `extra_data` as zero.
    ///
    /// For infallible paths such as EVM environment construction. A malformed header may be
    /// executed with a zero component before consensus rejects it; it is never admitted to the
    /// canonical chain.
    fn timestamp_millis_part(&self) -> u64 {
        timestamp_millis_part_or_zero(self.extra_data())
    }

    /// Returns the block time in Unix milliseconds, treating malformed `extra_data` as a zero
    /// sub-second component. See [`Self::timestamp_millis_part`].
    fn timestamp_millis(&self) -> u64 {
        join_timestamp_millis(self.timestamp(), self.timestamp_millis_part())
    }
}

impl<H: BlockHeader> SeismicBlockHeader for H {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::bytes;

    #[test]
    fn accessors_read_the_extra_data_prefix() {
        let header = Header {
            timestamp: 1_700_000_000,
            extra_data: encode_extra_data(123, b"reth").unwrap(),
            ..Default::default()
        };
        assert_eq!(header.try_timestamp_millis_part(), Ok(123));
        assert_eq!(header.timestamp_millis_part(), 123);
        assert_eq!(header.try_timestamp_millis(), Ok(1_700_000_000_123));
        assert_eq!(header.timestamp_millis(), 1_700_000_000_123);

        // The hash is the stock header hash: the part is part of the standard fields.
        let mut other = header.clone();
        other.extra_data = encode_extra_data(124, b"reth").unwrap();
        assert_ne!(header.hash_slow(), other.hash_slow());

        let malformed = Header { extra_data: bytes!("03e8"), ..header };
        assert_eq!(
            malformed.try_timestamp_millis_part(),
            Err(ExtraDataError::InvalidMillisPart(1000))
        );
        assert_eq!(malformed.timestamp_millis_part(), 0);
        assert_eq!(malformed.timestamp_millis(), 1_700_000_000_000);
    }
}
