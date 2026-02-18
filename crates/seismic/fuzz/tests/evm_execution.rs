//! Fuzz tests for full SeismicEvm transaction execution.
//!
//! DEPENDENCIES EXERCISED: [seismic-revm, alloy-seismic-evm, seismic-enclave]
//! CRASH CATEGORY: evm_execution
//!
//! This is the highest-priority fuzz target. It exercises the full
//! SeismicEvm.transact() path with arbitrary transactions. Any panic
//! here means a malicious transaction could crash a node.

use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::{Address, U256};
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
use reth_seismic_fuzz::{
    mock_evm::{fuzz_evm_env, fuzz_evm_factory},
    mock_state::new_seeded_db,
    tx_gen::FuzzSeismicTx,
};
use revm::state::AccountInfo;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// Full EVM transact with arbitrary transactions — must never panic.
    #[test]
    fn evm_transact_never_panics(input in arb::<FuzzSeismicTx>()) {
        let factory = fuzz_evm_factory();
        let evm_env = fuzz_evm_env();
        let mut db = new_seeded_db();

        // Give the caller a balance so transactions can pay gas
        let caller = Address::from(input.caller);
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        });

        let tx = input.into_seismic_tx();

        let mut evm = factory.create_evm(db, evm_env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));

        prop_assert!(result.is_ok(), "EVM PANIC during transact — this is a security bug");
    }

    /// Seismic tx type (0x4A) only — tests the privacy-specific execution path.
    #[test]
    fn evm_transact_seismic_tx_never_panics(input in arb::<FuzzSeismicTx>()) {
        let factory = fuzz_evm_factory();
        let evm_env = fuzz_evm_env();
        let mut db = new_seeded_db();

        let caller = Address::from(input.caller);
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        });

        // Force seismic tx type
        let mut tx = input.into_seismic_tx();
        tx.base.tx_type = 0x4A;

        let mut evm = factory.create_evm(db, evm_env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));

        prop_assert!(result.is_ok(), "EVM PANIC during seismic tx transact — this is a security bug");
    }

    /// EVM execution with Create transactions (deploy contracts).
    #[test]
    fn evm_create_tx_never_panics(input in arb::<FuzzSeismicTx>()) {
        let factory = fuzz_evm_factory();
        let evm_env = fuzz_evm_env();
        let mut db = new_seeded_db();

        let caller = Address::from(input.caller);
        db.insert_account_info(caller, AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        });

        // Force Create transaction
        let mut fuzz_input = input;
        fuzz_input.to_create = true;
        let tx = fuzz_input.into_seismic_tx();

        let mut evm = factory.create_evm(db, evm_env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));

        prop_assert!(result.is_ok(), "EVM PANIC during create tx — this is a security bug");
    }
}
