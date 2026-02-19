//! Pre-seeded state database for fuzz targets.
//!
//! Provides a `CacheDB` with funded accounts so that arbitrary transactions
//! have counterparties to interact with.

use alloy_primitives::{Address, Bytes, U256};
use revm::{
    database::CacheDB,
    database_interface::EmptyDBTyped,
    state::{AccountInfo, Bytecode},
};

/// Seed a `CacheDB` with standard test accounts for fuzzing.
///
/// Creates:
/// - A richly funded account at `Address::with_last_byte(1)`
/// - A contract account at `Address::with_last_byte(2)` with simple identity bytecode
/// - Additional funded accounts at bytes 3-10 for interaction targets
pub fn seed_default_accounts(db: &mut CacheDB<EmptyDBTyped<core::convert::Infallible>>) {
    let balance = U256::from(10u128.pow(18) * 1_000_000);

    // Primary funded account
    db.insert_account_info(
        Address::with_last_byte(1),
        AccountInfo { balance, nonce: 0, code_hash: Default::default(), code: None },
    );

    // Contract with identity bytecode (copies input to output)
    // CALLDATASIZE PUSH1 0 PUSH1 0 CALLDATACOPY CALLDATASIZE PUSH1 0 RETURN
    // 36 60 00 60 00 37 36 60 00 F3
    let identity_code =
        Bytes::from(vec![0x36, 0x60, 0x00, 0x60, 0x00, 0x37, 0x36, 0x60, 0x00, 0xF3]);
    db.insert_account_info(
        Address::with_last_byte(2),
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: Default::default(),
            code: Some(Bytecode::new_raw(identity_code)),
        },
    );

    // Additional funded accounts for interaction targets
    for i in 3..=10 {
        db.insert_account_info(
            Address::with_last_byte(i),
            AccountInfo { balance, nonce: 0, code_hash: Default::default(), code: None },
        );
    }
}

/// Create a fresh `CacheDB` pre-seeded with default accounts.
pub fn new_seeded_db() -> CacheDB<EmptyDBTyped<core::convert::Infallible>> {
    let mut db = CacheDB::new(EmptyDBTyped::default());
    seed_default_accounts(&mut db);
    db
}
