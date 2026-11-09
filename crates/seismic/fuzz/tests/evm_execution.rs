//! Fuzz tests for full `SeismicEvm` transaction execution.
//!
//! DEPENDENCIES EXERCISED: [`seismic-revm`, `alloy-seismic-evm`, `seismic-crypto`]
//! CRASH CATEGORY: `evm_execution`
//!
//! This is the highest-priority fuzz target. It exercises the full
//! `SeismicEvm.transact()` path with arbitrary transactions. Any panic
//! here means a malicious transaction could crash a node.

use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::Address;
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
use reth_seismic_fuzz::{
    mock_evm::{fuzz_evm_env, fuzz_evm_factory},
    mock_state::{funded_account, new_seeded_db},
    tx_gen::FuzzSeismicTx,
};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn evm_transact_never_panics(input in arb::<FuzzSeismicTx>()) {
        let mut db = new_seeded_db();
        db.insert_account_info(Address::from(input.caller), funded_account());

        let tx = input.into_seismic_tx();
        let mut evm = fuzz_evm_factory().create_evm(db, fuzz_evm_env());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));
        prop_assert!(result.is_ok(), "EVM PANIC during transact — security bug");
    }

    /// Seismic tx type (0x4A) only — tests the privacy-specific execution path.
    #[test]
    fn evm_transact_seismic_tx_never_panics(input in arb::<FuzzSeismicTx>()) {
        let mut db = new_seeded_db();
        db.insert_account_info(Address::from(input.caller), funded_account());

        let mut tx = input.into_seismic_tx();
        tx.base.tx_type = 0x4A;
        let mut evm = fuzz_evm_factory().create_evm(db, fuzz_evm_env());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));
        prop_assert!(result.is_ok(), "EVM PANIC during seismic tx transact — security bug");
    }

    #[test]
    fn evm_create_tx_never_panics(input in arb::<FuzzSeismicTx>()) {
        let mut db = new_seeded_db();
        db.insert_account_info(Address::from(input.caller), funded_account());

        let mut fuzz_input = input;
        fuzz_input.to_create = true;
        let tx = fuzz_input.into_seismic_tx();
        let mut evm = fuzz_evm_factory().create_evm(db, fuzz_evm_env());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.transact(tx)
        }));
        prop_assert!(result.is_ok(), "EVM PANIC during create tx — security bug");
    }
}
