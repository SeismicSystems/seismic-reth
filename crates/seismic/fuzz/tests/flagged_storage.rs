//! Fuzz tests for flagged storage access control (`SLOAD`/`CLOAD`/`SSTORE`/`CSTORE`).
//!
//! DEPENDENCIES EXERCISED: [`seismic-revm`]
//! CRASH CATEGORY: flagged_storage
//!
//! Tests the privacy boundary enforcement between public and private storage.
//! Any panic here is a security bug.

use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use proptest::prelude::*;
use reth_seismic_fuzz::{
    mock_evm::{fuzz_evm_env, fuzz_evm_factory},
    mock_state::{funded_account, new_seeded_db, FUZZ_CHAIN_ID},
};
use revm::{
    context::TxEnv,
    database::CacheDB,
    database_interface::EmptyDBTyped,
    state::{AccountInfo, Bytecode},
};
use seismic_revm::transaction::abstraction::{RngMode, SeismicTransaction};

fn call_tx(caller: Address, contract_addr: Address, gas_limit: u32) -> SeismicTransaction<TxEnv> {
    SeismicTransaction {
        base: TxEnv {
            caller,
            gas_limit: gas_limit as u64,
            gas_price: 0,
            gas_priority_fee: None,
            kind: TxKind::Call(contract_addr),
            value: U256::ZERO,
            data: Bytes::new(),
            chain_id: Some(FUZZ_CHAIN_ID),
            nonce: 0,
            access_list: Default::default(),
            blob_hashes: Default::default(),
            max_fee_per_blob_gas: Default::default(),
            authorization_list: Default::default(),
            tx_type: 0,
        },
        tx_hash: Default::default(),
        rng_mode: RngMode::Execution,
    }
}

fn deploy_contract(
    db: &mut CacheDB<EmptyDBTyped<core::convert::Infallible>>,
    addr_byte: u8,
    bytecode: Vec<u8>,
) -> Address {
    let addr = Address::with_last_byte(addr_byte);
    db.insert_account_info(
        addr,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: Default::default(),
            code: Some(Bytecode::new_raw(Bytes::from(bytecode))),
        },
    );
    addr
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// SLOAD on arbitrary storage slots — must not panic.
    #[test]
    fn sload_execution_never_panics(
        slot_index in any::<[u8; 32]>(),
        caller_bytes in any::<[u8; 20]>(),
        gas_limit in 21_000u32..1_000_000,
    ) {
        let mut db = new_seeded_db();
        let caller = Address::from(caller_bytes);
        db.insert_account_info(caller, funded_account());

        // PUSH32 <slot> SLOAD STOP
        let mut bytecode = vec![0x7F];
        bytecode.extend_from_slice(&slot_index);
        bytecode.push(0x54); // SLOAD
        bytecode.push(0x00); // STOP
        let contract_addr = deploy_contract(&mut db, 0xAA, bytecode);

        let mut evm = fuzz_evm_factory().create_evm(db, fuzz_evm_env());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(call_tx(caller, contract_addr, gas_limit))
        }));
        prop_assert!(result.is_ok(), "SLOAD execution PANIC — security bug");
    }

    /// CLOAD (0xB0) on arbitrary storage slots — must not panic.
    #[test]
    fn cload_execution_never_panics(
        slot_index in any::<[u8; 32]>(),
        caller_bytes in any::<[u8; 20]>(),
        gas_limit in 21_000u32..1_000_000,
    ) {
        let mut db = new_seeded_db();
        let caller = Address::from(caller_bytes);
        db.insert_account_info(caller, funded_account());

        // PUSH32 <slot> CLOAD STOP
        let mut bytecode = vec![0x7F];
        bytecode.extend_from_slice(&slot_index);
        bytecode.push(0xB0); // CLOAD
        bytecode.push(0x00); // STOP
        let contract_addr = deploy_contract(&mut db, 0xBB, bytecode);

        let mut evm = fuzz_evm_factory().create_evm(db, fuzz_evm_env());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(call_tx(caller, contract_addr, gas_limit))
        }));
        prop_assert!(result.is_ok(), "CLOAD execution PANIC — security bug");
    }

    /// CSTORE (0xB1) with arbitrary slot/value — must not panic.
    #[test]
    fn cstore_execution_never_panics(
        slot_index in any::<[u8; 32]>(),
        value_bytes in any::<[u8; 32]>(),
        caller_bytes in any::<[u8; 20]>(),
        gas_limit in 21_000u32..1_000_000,
    ) {
        let mut db = new_seeded_db();
        let caller = Address::from(caller_bytes);
        db.insert_account_info(caller, funded_account());

        // PUSH32 <value> PUSH32 <slot> CSTORE STOP
        let mut bytecode = vec![0x7F];
        bytecode.extend_from_slice(&value_bytes);
        bytecode.push(0x7F);
        bytecode.extend_from_slice(&slot_index);
        bytecode.push(0xB1); // CSTORE
        bytecode.push(0x00); // STOP
        let contract_addr = deploy_contract(&mut db, 0xCC, bytecode);

        let mut evm = fuzz_evm_factory().create_evm(db, fuzz_evm_env());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(call_tx(caller, contract_addr, gas_limit))
        }));
        prop_assert!(result.is_ok(), "CSTORE execution PANIC — security bug");
    }
}
