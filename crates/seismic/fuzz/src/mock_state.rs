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

/// 1M ETH in wei
const FUZZ_BALANCE: u128 = 10u128.pow(18) * 1_000_000;

fn funded_account() -> AccountInfo {
    AccountInfo {
        balance: U256::from(FUZZ_BALANCE),
        nonce: 0,
        code_hash: Default::default(),
        code: None,
    }
}

/// Seeds accounts at addresses 0x01..0x0A:
/// - 0x01 and 0x03-0x0A: funded EOAs
/// - 0x02: identity contract (copies calldata to output)
pub fn seed_default_accounts(db: &mut CacheDB<EmptyDBTyped<core::convert::Infallible>>) {
    db.insert_account_info(Address::with_last_byte(1), funded_account());

    // CALLDATASIZE PUSH1 0 PUSH1 0 CALLDATACOPY CALLDATASIZE PUSH1 0 RETURN
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

    for i in 3..=10 {
        db.insert_account_info(Address::with_last_byte(i), funded_account());
    }
}

pub fn new_seeded_db() -> CacheDB<EmptyDBTyped<core::convert::Infallible>> {
    let mut db = CacheDB::new(EmptyDBTyped::default());
    seed_default_accounts(&mut db);
    db
}
