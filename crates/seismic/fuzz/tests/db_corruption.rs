//! Integration test: corrupt database entry triggers zstd decompressor panic.
//!
//! Validates the full code path:
//!   MDBX read → decode_one → Decompress::decompress → from_compact → zstd decompress → PANIC
//!
//! This test writes a valid transaction to the Transactions table, then overwrites
//! it with corrupt bytes via RawTable, and reads it back through the normal path.

use alloy_consensus::TxLegacy;
use alloy_primitives::{Signature, TxKind, U256};
use reth_db::{tables, test_utils::create_test_rw_db};
use reth_db_api::{
    cursor::DbCursorRW,
    table::Table,
    tables::{RawKey, RawTable, RawValue},
    transaction::{DbTx, DbTxMut},
    Database,
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

/// Write a valid tx, then overwrite with corrupt bytes that have the zstd flag set.
/// Reading back through the normal Transactions table should panic in the zstd decompressor.
#[test]
fn corrupt_db_entry_panics_in_zstd_decompressor() {
    let db = create_test_rw_db();
    let tx_num: u64 = 0;
    let valid_tx = valid_test_tx();

    // Step 1: Write a valid transaction through the normal path
    {
        let rw_tx = db.tx_mut().expect("failed to open write tx");
        rw_tx.put::<TxTable>(tx_num, valid_tx.clone()).expect("failed to write tx");
        rw_tx.commit().expect("failed to commit");
    }

    // Step 2: Verify we can read it back correctly
    {
        let ro_tx = db.tx().expect("failed to open read tx");
        let readback = ro_tx.get::<TxTable>(tx_num).expect("failed to read tx");
        assert!(readback.is_some(), "transaction should exist");
    }

    // Step 3: Overwrite with corrupt bytes that have the zstd flag set.
    //
    // Compact layout of SeismicTransactionSigned:
    //   byte 0:       flags — bit 0: sig high bit, bits 1-2: tx type, bit 3: zstd flag
    //   bytes 1-64:   signature (r: 32 bytes, s: 32 bytes)
    //   bytes 65+:    transaction body (zstd compressed if bit 3 is set)
    //
    // We need 65+ bytes so the signature parser doesn't panic before
    // reaching the zstd decompressor. Byte 0 = 0x08 sets zstd=1.
    // Bytes 65+ are garbage — not a valid zstd frame.
    {
        let rw_tx = db.tx_mut().expect("failed to open write tx");
        let key = RawKey::<u64>::new(tx_num);

        let mut corrupt_bytes = vec![0x08]; // flags: zstd=1, tx_type=0, sig_bit=0
        corrupt_bytes.extend_from_slice(&[0x01; 64]); // 64 bytes of fake signature
        corrupt_bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]); // garbage "zstd" data
        let corrupt_value = RawValue::<<TxTable as Table>::Value>::from_vec(corrupt_bytes);

        let mut cursor = rw_tx
            .cursor_write::<RawTable<TxTable>>()
            .expect("failed to open cursor");
        cursor.upsert(key, &corrupt_value).expect("failed to write corrupt data");
        rw_tx.commit().expect("failed to commit corrupt data");
    }

    // Step 4: Read through the normal path — this should hit the zstd decompressor
    // and panic with "Failed to decompress N bytes: Unknown frame descriptor"
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ro_tx = db.tx().expect("failed to open read tx");
        ro_tx.get::<TxTable>(tx_num)
    }));

    match &result {
        Err(panic_payload) => {
            // Extract the panic message
            let msg = if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.as_str()
            } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s
            } else {
                "unknown panic"
            };
            eprintln!("Confirmed panic on corrupt DB read: {msg}");
            assert!(
                msg.contains("Failed to decompress"),
                "Expected zstd decompressor panic, got: {msg}"
            );
        }
        Ok(Ok(Some(_))) => {
            panic!("Should have panicked on corrupt data, but got a valid transaction back");
        }
        Ok(Ok(None)) => {
            panic!("Should have panicked on corrupt data, but got None (entry missing)");
        }
        Ok(Err(db_err)) => {
            // If we get here, the decompressor returned an error instead of panicking.
            // This would mean the bug is fixed — the test should be updated.
            eprintln!("Got DatabaseError instead of panic: {db_err:?}");
            eprintln!("The zstd decompressor is now returning errors correctly — update this test");
            // For now, this is actually the DESIRED behavior, so pass
        }
    }
}
