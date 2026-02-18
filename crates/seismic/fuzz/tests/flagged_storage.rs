//! Fuzz tests for flagged storage access control (SLOAD/CLOAD/SSTORE/CSTORE).
//!
//! DEPENDENCIES EXERCISED: [seismic-revm]
//! CRASH CATEGORY: flagged_storage
//!
//! Tests the privacy boundary enforcement between public and private storage.
//! Uses the interpreter directly (not full EVM) to isolate the storage
//! instruction logic. Any panic here is a security bug.

use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::{Address, Bytes, U256};
use proptest::prelude::*;
use reth_seismic_fuzz::{
    mock_evm::{fuzz_evm_env, fuzz_evm_factory},
    mock_state::new_seeded_db,
};
use revm::state::{AccountInfo, Bytecode};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// Deploy and call contract with SLOAD opcode — must not panic.
    /// SLOAD should work for public storage, halt for private storage.
    #[test]
    fn sload_execution_never_panics(
        slot_index in any::<[u8; 32]>(),
        caller_bytes in any::<[u8; 20]>(),
        gas_limit in 21_000u32..1_000_000,
    ) {
        let factory = fuzz_evm_factory();
        let evm_env = fuzz_evm_env();
        let mut db = new_seeded_db();

        let caller = Address::from(caller_bytes);
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        });

        // Deploy a contract that does: PUSH32 <slot> SLOAD STOP
        // 7F <32 bytes> 54 00
        let mut bytecode = vec![0x7F]; // PUSH32
        bytecode.extend_from_slice(&slot_index);
        bytecode.push(0x54); // SLOAD
        bytecode.push(0x00); // STOP

        let contract_addr = Address::with_last_byte(0xAA);
        db.insert_account_info(contract_addr, AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: Default::default(),
            code: Some(Bytecode::new_raw(Bytes::from(bytecode))),
        });

        let tx = seismic_revm::transaction::abstraction::SeismicTransaction {
            base: revm::context::TxEnv {
                caller,
                gas_limit: gas_limit as u64,
                gas_price: 0,
                gas_priority_fee: None,
                kind: alloy_primitives::TxKind::Call(contract_addr),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: Some(5123),
                nonce: 0,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 0,
            },
            tx_hash: Default::default(),
            rng_mode: seismic_revm::transaction::abstraction::RngMode::Execution,
        };

        let mut evm = factory.create_evm(db, evm_env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));

        prop_assert!(result.is_ok(), "SLOAD execution PANIC — security bug");
    }

    /// Deploy and call contract with CLOAD opcode — must not panic.
    /// CLOAD (0xB0) should work for private storage, halt for public storage.
    #[test]
    fn cload_execution_never_panics(
        slot_index in any::<[u8; 32]>(),
        caller_bytes in any::<[u8; 20]>(),
        gas_limit in 21_000u32..1_000_000,
    ) {
        let factory = fuzz_evm_factory();
        let evm_env = fuzz_evm_env();
        let mut db = new_seeded_db();

        let caller = Address::from(caller_bytes);
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        });

        // Deploy a contract that does: PUSH32 <slot> CLOAD STOP
        // 7F <32 bytes> B0 00
        let mut bytecode = vec![0x7F]; // PUSH32
        bytecode.extend_from_slice(&slot_index);
        bytecode.push(0xB0); // CLOAD
        bytecode.push(0x00); // STOP

        let contract_addr = Address::with_last_byte(0xBB);
        db.insert_account_info(contract_addr, AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: Default::default(),
            code: Some(Bytecode::new_raw(Bytes::from(bytecode))),
        });

        let tx = seismic_revm::transaction::abstraction::SeismicTransaction {
            base: revm::context::TxEnv {
                caller,
                gas_limit: gas_limit as u64,
                gas_price: 0,
                gas_priority_fee: None,
                kind: alloy_primitives::TxKind::Call(contract_addr),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: Some(5123),
                nonce: 0,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 0,
            },
            tx_hash: Default::default(),
            rng_mode: seismic_revm::transaction::abstraction::RngMode::Execution,
        };

        let mut evm = factory.create_evm(db, evm_env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));

        prop_assert!(result.is_ok(), "CLOAD execution PANIC — security bug");
    }

    /// Deploy and call contract with CSTORE opcode — must not panic.
    #[test]
    fn cstore_execution_never_panics(
        slot_index in any::<[u8; 32]>(),
        value_bytes in any::<[u8; 32]>(),
        caller_bytes in any::<[u8; 20]>(),
        gas_limit in 21_000u32..1_000_000,
    ) {
        let factory = fuzz_evm_factory();
        let evm_env = fuzz_evm_env();
        let mut db = new_seeded_db();

        let caller = Address::from(caller_bytes);
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        });

        // Deploy a contract that does: PUSH32 <value> PUSH32 <slot> CSTORE STOP
        // 7F <32 bytes> 7F <32 bytes> B1 00
        let mut bytecode = vec![0x7F]; // PUSH32 value
        bytecode.extend_from_slice(&value_bytes);
        bytecode.push(0x7F); // PUSH32 slot index
        bytecode.extend_from_slice(&slot_index);
        bytecode.push(0xB1); // CSTORE
        bytecode.push(0x00); // STOP

        let contract_addr = Address::with_last_byte(0xCC);
        db.insert_account_info(contract_addr, AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: Default::default(),
            code: Some(Bytecode::new_raw(Bytes::from(bytecode))),
        });

        let tx = seismic_revm::transaction::abstraction::SeismicTransaction {
            base: revm::context::TxEnv {
                caller,
                gas_limit: gas_limit as u64,
                gas_price: 0,
                gas_priority_fee: None,
                kind: alloy_primitives::TxKind::Call(contract_addr),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: Some(5123),
                nonce: 0,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 0,
            },
            tx_hash: Default::default(),
            rng_mode: seismic_revm::transaction::abstraction::RngMode::Execution,
        };

        let mut evm = factory.create_evm(db, evm_env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));

        prop_assert!(result.is_ok(), "CSTORE execution PANIC — security bug");
    }
}
