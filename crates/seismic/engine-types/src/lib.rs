//! Engine API wire types and header conventions shared between seismic-reth and the Summit
//! consensus client.
//!
//! Seismic block headers are **stock Ethereum headers**: `timestamp` is in Unix seconds and the
//! block hash is the standard header hash. The sub-second component of the block time,
//! `timestampMillisPart` (`0..1000`), is carried in the first two bytes of `extraData`
//! (see [`extra_data`]). Execution payloads are therefore the stock Engine API types; only the
//! payload *attributes* are extended with an explicit `timestampMillisPart` so the consensus
//! layer can request sub-second block times.
//!
//! This crate depends on stock `alloy` only so it can be consumed by Summit (which does not
//! build against the Seismic alloy/reth forks). The node-side integration (built payloads,
//! builder attributes) lives in `reth-seismic-engine-primitives`.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod attributes;
pub use attributes::SeismicPayloadAttributes;

pub mod extra_data;
pub use extra_data::{
    builder_extra_data, decode_timestamp_millis_part, encode_extra_data, header_timestamp_millis,
    timestamp_millis_part_or_zero, ExtraDataError, MAX_BUILDER_EXTRA_DATA_LEN, MAX_EXTRA_DATA_LEN,
    TIMESTAMP_MILLIS_PREFIX_LEN,
};

/// Number of milliseconds in one second.
pub const MILLIS_PER_SECOND: u64 = 1000;

/// Splits a Unix millisecond timestamp into `(seconds, millis_part)`.
pub const fn split_timestamp_millis(timestamp_millis: u64) -> (u64, u64) {
    (timestamp_millis / MILLIS_PER_SECOND, timestamp_millis % MILLIS_PER_SECOND)
}

/// Combines Unix seconds and a sub-second millisecond component into Unix milliseconds.
///
/// Saturates instead of wrapping on overflow.
pub const fn join_timestamp_millis(timestamp: u64, timestamp_millis_part: u64) -> u64 {
    timestamp.saturating_mul(MILLIS_PER_SECOND).saturating_add(timestamp_millis_part)
}

/// Returns `true` if `timestamp_millis_part` is a valid sub-second component.
pub const fn is_valid_millis_part(timestamp_millis_part: u64) -> bool {
    timestamp_millis_part < MILLIS_PER_SECOND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_join_roundtrip() {
        for ms in [0u64, 1, 999, 1000, 1001, 1_700_000_000_123, u64::MAX - 1] {
            let (secs, part) = split_timestamp_millis(ms);
            assert!(is_valid_millis_part(part));
            assert_eq!(join_timestamp_millis(secs, part), ms);
        }
        assert_eq!(join_timestamp_millis(u64::MAX, 999), u64::MAX);
        assert!(!is_valid_millis_part(1000));
    }
}
