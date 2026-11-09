//! The `extraData` layout that carries the sub-second timestamp component.
//!
//! Seismic headers are stock Ethereum headers. The sub-second (milliseconds) component of the
//! block time lives in the first [`TIMESTAMP_MILLIS_PREFIX_LEN`] bytes of `extraData` as a
//! big-endian integer in `0..1000`; the remaining bytes (at most [`MAX_BUILDER_EXTRA_DATA_LEN`])
//! are free-form builder data, as on Ethereum.
//!
//! ```text
//! extraData = [millis_part: u16 BE][builder data: 0..=30 bytes]
//! ```

use crate::{is_valid_millis_part, join_timestamp_millis, MILLIS_PER_SECOND};
use alloc::vec::Vec;
use alloy_primitives::Bytes;

/// Length of the sub-second timestamp prefix in `extraData`.
pub const TIMESTAMP_MILLIS_PREFIX_LEN: usize = 2;

/// Maximum `extraData` length allowed by Ethereum consensus (post-merge).
pub const MAX_EXTRA_DATA_LEN: usize = 32;

/// Maximum length of the builder-controlled part of `extraData`, after the timestamp prefix.
pub const MAX_BUILDER_EXTRA_DATA_LEN: usize = MAX_EXTRA_DATA_LEN - TIMESTAMP_MILLIS_PREFIX_LEN;

/// Error returned when `extraData` does not follow the Seismic layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraDataError {
    /// `extraData` is shorter than the timestamp prefix.
    TooShort {
        /// The actual length.
        len: usize,
    },
    /// `extraData` exceeds the consensus maximum.
    TooLong {
        /// The actual length.
        len: usize,
    },
    /// The builder data exceeds the space left after the timestamp prefix.
    BuilderDataTooLong {
        /// The actual builder data length.
        len: usize,
    },
    /// The encoded sub-second component is not in `0..1000`.
    InvalidMillisPart(u64),
}

impl core::fmt::Display for ExtraDataError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { len } => write!(
                f,
                "extraData is {len} bytes, expected at least the {TIMESTAMP_MILLIS_PREFIX_LEN}-byte timestampMillisPart prefix"
            ),
            Self::TooLong { len } => {
                write!(f, "extraData is {len} bytes, expected at most {MAX_EXTRA_DATA_LEN}")
            }
            Self::BuilderDataTooLong { len } => write!(
                f,
                "builder extraData is {len} bytes, expected at most {MAX_BUILDER_EXTRA_DATA_LEN} after the timestampMillisPart prefix"
            ),
            Self::InvalidMillisPart(part) => {
                write!(f, "timestampMillisPart {part} is out of range (expected 0..{MILLIS_PER_SECOND})")
            }
        }
    }
}

impl core::error::Error for ExtraDataError {}

/// Encodes the sub-second component and the builder data into Seismic `extraData`.
pub fn encode_extra_data(
    timestamp_millis_part: u64,
    builder_data: &[u8],
) -> Result<Bytes, ExtraDataError> {
    if !is_valid_millis_part(timestamp_millis_part) {
        return Err(ExtraDataError::InvalidMillisPart(timestamp_millis_part))
    }
    if builder_data.len() > MAX_BUILDER_EXTRA_DATA_LEN {
        return Err(ExtraDataError::BuilderDataTooLong { len: builder_data.len() })
    }
    let mut out = Vec::with_capacity(TIMESTAMP_MILLIS_PREFIX_LEN + builder_data.len());
    // `timestamp_millis_part < 1000` fits in a u16.
    out.extend_from_slice(&(timestamp_millis_part as u16).to_be_bytes());
    out.extend_from_slice(builder_data);
    Ok(out.into())
}

/// Validates the Seismic `extraData` layout and decodes the sub-second component.
pub fn decode_timestamp_millis_part(extra_data: &[u8]) -> Result<u64, ExtraDataError> {
    if extra_data.len() > MAX_EXTRA_DATA_LEN {
        return Err(ExtraDataError::TooLong { len: extra_data.len() })
    }
    let Some(prefix) = extra_data.first_chunk::<TIMESTAMP_MILLIS_PREFIX_LEN>() else {
        return Err(ExtraDataError::TooShort { len: extra_data.len() })
    };
    let part = u64::from(u16::from_be_bytes(*prefix));
    if !is_valid_millis_part(part) {
        return Err(ExtraDataError::InvalidMillisPart(part))
    }
    Ok(part)
}

/// Returns the builder data that follows the timestamp prefix, or an empty slice if the
/// `extraData` is too short to carry one.
pub fn builder_extra_data(extra_data: &[u8]) -> &[u8] {
    extra_data.get(TIMESTAMP_MILLIS_PREFIX_LEN..).unwrap_or_default()
}

/// Decodes the sub-second component, treating malformed `extraData` as a zero component.
///
/// For infallible paths (EVM environment construction) only. A malformed header may still be
/// *executed* with a zero component (the engine tree executes a payload before running the
/// consensus checks on it), but consensus rejects it afterwards, so such a header is never
/// admitted to the canonical chain and this decode never observes one on it.
pub fn timestamp_millis_part_or_zero(extra_data: &[u8]) -> u64 {
    decode_timestamp_millis_part(extra_data).unwrap_or_default()
}

/// Reconstructs the Unix millisecond block time from a header's seconds `timestamp` and its
/// `extraData`.
pub fn header_timestamp_millis(timestamp: u64, extra_data: &[u8]) -> Result<u64, ExtraDataError> {
    decode_timestamp_millis_part(extra_data).map(|part| join_timestamp_millis(timestamp, part))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes;

    #[test]
    fn encode_decode_roundtrip() {
        for part in [0, 1, 123, 999] {
            for builder in [&b""[..], b"reth", &[0xffu8; MAX_BUILDER_EXTRA_DATA_LEN]] {
                let encoded = encode_extra_data(part, builder).unwrap();
                assert_eq!(encoded.len(), TIMESTAMP_MILLIS_PREFIX_LEN + builder.len());
                assert_eq!(decode_timestamp_millis_part(&encoded), Ok(part));
                assert_eq!(builder_extra_data(&encoded), builder);
                assert_eq!(timestamp_millis_part_or_zero(&encoded), part);
                assert_eq!(header_timestamp_millis(7, &encoded), Ok(7000 + part));
            }
        }
        assert_eq!(encode_extra_data(123, b"ab").unwrap(), bytes!("007b6162"));
    }

    #[test]
    fn encode_rejects_out_of_range_inputs() {
        assert_eq!(encode_extra_data(1000, b""), Err(ExtraDataError::InvalidMillisPart(1000)));
        assert_eq!(
            encode_extra_data(0, &[0u8; MAX_BUILDER_EXTRA_DATA_LEN + 1]),
            Err(ExtraDataError::BuilderDataTooLong { len: MAX_BUILDER_EXTRA_DATA_LEN + 1 })
        );
    }

    #[test]
    fn decode_rejects_malformed_layouts() {
        assert_eq!(decode_timestamp_millis_part(b""), Err(ExtraDataError::TooShort { len: 0 }));
        assert_eq!(decode_timestamp_millis_part(b"\x00"), Err(ExtraDataError::TooShort { len: 1 }));
        assert_eq!(
            decode_timestamp_millis_part(&[0u8; MAX_EXTRA_DATA_LEN + 1]),
            Err(ExtraDataError::TooLong { len: MAX_EXTRA_DATA_LEN + 1 })
        );
        assert_eq!(
            decode_timestamp_millis_part(&bytes!("03e8")),
            Err(ExtraDataError::InvalidMillisPart(1000))
        );
        // A stock reth builder tag is rejected by the range check.
        assert_eq!(
            decode_timestamp_millis_part(b"reth/v1.0.0/linux"),
            Err(ExtraDataError::InvalidMillisPart(0x7265))
        );
        assert_eq!(timestamp_millis_part_or_zero(b""), 0);
        assert_eq!(builder_extra_data(b"\x00"), b"");
    }
}
