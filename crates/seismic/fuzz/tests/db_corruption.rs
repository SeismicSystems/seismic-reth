//! Integration test: corrupt database entries return DatabaseError::Decode.
//!
//! Validates the full production code path:
//!   MDBX read → decode_one → Decompress::decompress → catch_unwind(from_compact) → DatabaseError
//!
//! The zstd decompressor panics on malformed data, but Decompress::decompress
//! catches it and converts to DatabaseError::Decode. This prevents the node from
//! crashing on corrupt DB entries (see: github.com/paradigmxyz/reth/issues/16052).

use alloy_consensus::TxLegacy;
use alloy_primitives::{Signature, TxKind, U256};
use reth_db::{tables, test_utils::create_test_rw_db};
use reth_db_api::{
    cursor::DbCursorRW,
    table::Table,
    tables::{RawKey, RawTable, RawValue},
    transaction::{DbTx, DbTxMut},
    Database, DatabaseError,
};
use reth_seismic_primitives::SeismicTransactionSigned;
use seismic_alloy_consensus::SeismicTypedTransaction;

type TxTable = tables::Transactions<SeismicTransactionSigned>;

fn valid_test_tx() -> SeismicTransactionSigned {
    let inner = TxLegacy {
        chain_id: Some(1),
        nonce: 0,
        gas_price: 21_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(alloy_primitives::Address::ZERO),
        value: U256::from(1_000_000),
        input: Default::default(),
    };
    SeismicTransactionSigned::new_unhashed(
        SeismicTypedTransaction::Legacy(inner),
        Signature::new(U256::from(1), U256::from(2), false),
    )
}

#[test]
fn corrupt_db_entry_returns_decode_error() {
    let db = create_test_rw_db();
    let tx_num: u64 = 0;

    // Write a valid transaction
    {
        let rw_tx = db.tx_mut().expect("failed to open write tx");
        rw_tx.put::<TxTable>(tx_num, valid_test_tx()).expect("failed to write tx");
        rw_tx.commit().expect("failed to commit");
    }

    // Verify it reads back correctly
    {
        let ro_tx = db.tx().expect("failed to open read tx");
        assert!(ro_tx.get::<TxTable>(tx_num).expect("failed to read tx").is_some());
    }

    // Overwrite with corrupt bytes that have the zstd flag set.
    //
    // Compact layout of SeismicTransactionSigned:
    //   byte 0:       flags — bit 0: sig high bit, bits 1-2: tx type, bit 3: zstd flag
    //   bytes 1-64:   signature (r: 32 bytes, s: 32 bytes)
    //   bytes 65+:    transaction body (zstd compressed if bit 3 is set)
    //
    // 0x08 = zstd flag set. 64 bytes fake signature. Remaining bytes are
    // garbage that the zstd decompressor will reject.
    {
        let rw_tx = db.tx_mut().expect("failed to open write tx");
        let key = RawKey::<u64>::new(tx_num);

        let mut corrupt_bytes = vec![0x08];
        corrupt_bytes.extend_from_slice(&[0x01; 64]);
        corrupt_bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let corrupt_value = RawValue::<<TxTable as Table>::Value>::from_vec(corrupt_bytes);

        let mut cursor = rw_tx.cursor_write::<RawTable<TxTable>>().expect("failed to open cursor");
        cursor.upsert(key, &corrupt_value).expect("failed to write corrupt data");
        rw_tx.commit().expect("failed to commit corrupt data");
    }

    // Capture the internal panic message to verify zstd decompressor fired
    let panic_msg = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let panic_msg_clone = panic_msg.clone();
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(msg) = info.payload().downcast_ref::<String>() {
            *panic_msg_clone.lock().unwrap() = msg.clone();
        } else if let Some(msg) = info.payload().downcast_ref::<&str>() {
            *panic_msg_clone.lock().unwrap() = msg.to_string();
        }
    }));

    // Read through the normal production path — should get DatabaseError::Decode, not a panic
    let ro_tx = db.tx().expect("failed to open read tx");
    let result: Result<Option<SeismicTransactionSigned>, DatabaseError> =
        ro_tx.get::<TxTable>(tx_num);

    std::panic::set_hook(prev_hook);

    assert!(result.is_err(), "corrupt data should return an error, not succeed");
    assert!(
        matches!(result, Err(DatabaseError::Decode)),
        "expected DatabaseError::Decode, got: {:?}",
        result,
    );

    // Verify the zstd decompressor panic actually fired inside catch_unwind
    let captured = panic_msg.lock().unwrap();
    assert!(
        captured.contains("Failed to decompress"),
        "expected zstd panic to fire internally, got: '{captured}'",
    );
}
