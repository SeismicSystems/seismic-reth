//! Differential fuzz tests: plain revm vs Seismic EVM.
//!
//! DEPENDENCIES EXERCISED: [seismic-revm, alloy-seismic-evm]
//! CRASH CATEGORY: differential
//!
//! For non-seismic transaction types (Legacy, EIP-2930, EIP-1559), the
//! SeismicEvm should produce identical results to plain revm.
//! Any divergence is a regression bug. Any panic is a security bug.

use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::{Address, U256};
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
use reth_seismic_fuzz::{
    mock_evm::{fuzz_evm_env, fuzz_evm_factory},
    tx_gen::FuzzSeismicTx,
};
use revm::{
    context::TxEnv,
    database::CacheDB,
    database_interface::EmptyDBTyped,
    handler::{ExecuteEvm, MainBuilder, MainnetContext},
    state::AccountInfo,
};
use seismic_revm::SeismicSpecId;

/// Seed a CacheDB with a funded caller.
fn seeded_db_with_caller(caller: Address) -> CacheDB<EmptyDBTyped<core::convert::Infallible>> {
    let mut db = CacheDB::new(EmptyDBTyped::default());
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(10u128.pow(18) * 1_000_000),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        },
    );
    db
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    /// Same non-seismic tx executed on both plain revm and SeismicEvm.
    /// Success/failure outcome must match. Any panic is a security bug.
    #[test]
    fn differential_eth_vs_seismic_outcome(input in arb::<FuzzSeismicTx>()) {
        // Force non-seismic tx type
        let seismic_tx = input.clone().into_eth_compatible_tx();
        let caller = seismic_tx.base.caller;

        // Create identical databases
        let db_seismic = seeded_db_with_caller(caller);
        let db_eth = seeded_db_with_caller(caller);

        // Build the plain TxEnv (same fields)
        let plain_tx = TxEnv {
            caller: seismic_tx.base.caller,
            gas_limit: seismic_tx.base.gas_limit,
            gas_price: seismic_tx.base.gas_price,
            gas_priority_fee: seismic_tx.base.gas_priority_fee,
            kind: seismic_tx.base.kind,
            value: seismic_tx.base.value,
            data: seismic_tx.base.data.clone(),
            chain_id: seismic_tx.base.chain_id,
            nonce: seismic_tx.base.nonce,
            access_list: seismic_tx.base.access_list.clone(),
            blob_hashes: seismic_tx.base.blob_hashes.clone(),
            max_fee_per_blob_gas: seismic_tx.base.max_fee_per_blob_gas,
            authorization_list: seismic_tx.base.authorization_list.clone(),
            tx_type: seismic_tx.base.tx_type,
        };

        // Execute on SeismicEvm (returns ResultAndState via alloy_evm::Evm::transact)
        let seismic_factory = fuzz_evm_factory();
        let seismic_env = fuzz_evm_env();
        let mut seismic_evm = seismic_factory.create_evm(db_seismic, seismic_env);
        let seismic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            seismic_evm.transact(seismic_tx)
        }));

        // Execute on plain revm (returns ExecutionResult via ExecuteEvm::transact_one)
        let eth_spec = SeismicSpecId::MERCURY.into_eth_spec();
        let mut plain_evm = MainnetContext::new(db_eth, eth_spec)
            .modify_cfg_chained(|cfg| {
                cfg.chain_id = 5123;
            })
            .build_mainnet();
        let eth_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            plain_evm.transact_one(plain_tx)
        }));

        // Both must not panic
        prop_assert!(seismic_result.is_ok(), "SeismicEvm PANIC — security bug");
        prop_assert!(eth_result.is_ok(), "Plain revm PANIC — security bug");

        let seismic_result = seismic_result.unwrap();
        let eth_result = eth_result.unwrap();

        // Compare outcomes: both should succeed or both should fail
        match (&seismic_result, &eth_result) {
            (Ok(seismic_out), Ok(eth_out)) => {
                // seismic_out is ResultAndState, eth_out is ExecutionResult
                let seismic_success = seismic_out.result.is_success();
                let eth_success = eth_out.is_success();
                prop_assert_eq!(
                    seismic_success, eth_success,
                    "Divergence: SeismicEvm success={}, EthEvm success={}",
                    seismic_success, eth_success
                );

                if seismic_success && eth_success {
                    let seismic_gas = seismic_out.result.gas_used();
                    let eth_gas = eth_out.gas_used();
                    prop_assert_eq!(
                        seismic_gas, eth_gas,
                        "Gas divergence: SeismicEvm={}, EthEvm={}",
                        seismic_gas, eth_gas
                    );

                    let seismic_output = seismic_out.result.output().cloned().unwrap_or_default();
                    let eth_output = eth_out.output().cloned().unwrap_or_default();
                    prop_assert_eq!(
                        seismic_output, eth_output,
                        "Output divergence between SeismicEvm and EthEvm"
                    );
                }
            }
            (Err(seismic_err), Err(eth_err)) => {
                let seismic_dbg = format!("{seismic_err:?}");
                let eth_dbg = format!("{eth_err:?}");
                // Both should fail with the same reason
                prop_assert_eq!(
                    seismic_dbg, eth_dbg,
                    "Both EVMs rejected the tx, but for different reasons"
                );
            }
            _ => {
                prop_assert!(
                    false,
                    "Divergence: one EVM succeeded and the other failed"
                );
            }
        }
    }
}
