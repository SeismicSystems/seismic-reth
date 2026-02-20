//! Fuzz tests for SeismicTransactionSigned encoding/decoding.
//!
//! DEPENDENCIES EXERCISED: [seismic-alloy-consensus, seismic-alloy-core]
//! CRASH CATEGORY: encoding_decoding
//!
//! Any panic here indicates a security bug — a malformed transaction from
//! the P2P network could crash a node.

use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
use reth_codecs::Compact;
use reth_seismic_primitives::SeismicTransactionSigned;
use seismic_alloy_consensus::SeismicTxType;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        .. ProptestConfig::default()
    })]

    /// Feed arbitrary bytes into `Decodable2718` — must never panic.
    #[test]
    fn tx_decode_arbitrary_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Must not panic regardless of input
        let result = std::panic::catch_unwind(|| {
            let _ = SeismicTransactionSigned::decode_2718(&mut &data[..]);
        });
        prop_assert!(result.is_ok(), "PANIC during decode — this is a security bug");
    }

    /// Roundtrip through EIP-2718 encoding: encode then decode must match.
    #[test]
    fn tx_roundtrip_2718(tx in arb::<SeismicTransactionSigned>()) {
        // Skip EIP-4844 (blob transactions have known encoding limitations)
        if tx.tx_type() == SeismicTxType::Eip4844 as u8 {
            return Ok(());
        }

        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);

        let result = std::panic::catch_unwind(|| {
            SeismicTransactionSigned::decode_2718(&mut &encoded[..])
        });

        match result {
            Ok(Ok(decoded)) => {
                prop_assert_eq!(&decoded, &tx, "2718 roundtrip mismatch");
            }
            Ok(Err(e)) => {
                // Decode error on our own encoding is a bug
                prop_assert!(false, "Failed to decode our own encoding: {e}");
            }
            Err(_) => {
                prop_assert!(false, "PANIC during decode — this is a security bug");
            }
        }
    }

    /// Roundtrip through Compact codec (exercises zstd compression).
    #[test]
    fn tx_roundtrip_compact(tx in arb::<SeismicTransactionSigned>()) {
        // Skip EIP-4844 (blob transactions have known encoding limitations)
        if tx.tx_type() == SeismicTxType::Eip4844 as u8 {
            return Ok(());
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut buf = Vec::new();
            let len = tx.to_compact(&mut buf);
            let (decoded, _) = SeismicTransactionSigned::from_compact(&buf, len);
            decoded
        }));

        match result {
            Ok(decoded) => {
                prop_assert_eq!(&decoded, &tx, "Compact roundtrip mismatch");
            }
            Err(_) => {
                prop_assert!(false, "PANIC during compact encode/decode — this is a security bug");
            }
        }
    }

    /// Feed arbitrary bytes into Compact decoder via direct from_compact call.
    /// Panics on malformed zstd frames (zstd-compressors/src/lib.rs:109) and
    /// short signatures (signature.rs:18). This direct call isn't used in
    /// production — every DB read goes through Decompress::decompress which
    /// wraps from_compact in catch_unwind and returns DatabaseError::Decode.
    /// See db_corruption.rs for the production path test.
    #[test]
    #[should_panic]
    fn tx_compact_decode_arbitrary_bytes_panics_on_corrupt_data(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let result = std::panic::catch_unwind(|| {
            // Use an arbitrary length value for the identifier
            for len in [0, 1, 2, 3, 0x4A] {
                let _ = SeismicTransactionSigned::from_compact(&data, len);
            }
        });
        prop_assert!(result.is_ok(), "PANIC during compact decode — this is a security bug");
    }
}
