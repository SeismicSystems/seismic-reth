#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use alloy_primitives::B256;
use reth_provider::ProviderError;
use revm::{
    context::TxEnv,
    state::{AccountInfo, Bytecode},
};
use seismic_revm::{
    gas_token_registry::{
        balance_storage_key, token_metadata_slot, TokenPrecision, GAS_TOKEN_REGISTRY,
        TOKEN_COUNT_SLOT,
    },
    SeismicTransaction,
};
use std::collections::HashMap;

const CALLER: Address = Address::repeat_byte(0x11);
const TOKEN: Address = Address::repeat_byte(0x22);
const OTHER: Address = Address::repeat_byte(0x33);
const ROOT: U256 = U256::from_limbs([3, 0, 0, 0x1234]);

#[derive(Default)]
struct MockDb {
    native: U256,
    slots: HashMap<(Address, U256), FlaggedStorage>,
    reads: Vec<(Address, U256)>,
    fail: Option<(Address, U256)>,
    fail_basic: bool,
    basic_reads: usize,
}

impl Database for MockDb {
    type Error = ProviderError;
    fn basic(&mut self, _: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_reads += 1;
        if self.fail_basic {
            return Err(ProviderError::InvalidStorageOutput)
        }
        Ok(Some(AccountInfo { balance: self.native, ..Default::default() }))
    }
    fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }
    fn block_hash(&mut self, _: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
    fn storage(&mut self, address: Address, key: U256) -> Result<FlaggedStorage, Self::Error> {
        self.reads.push((address, key));
        if self.fail == Some((address, key)) {
            return Err(ProviderError::InvalidStorageOutput)
        }
        Ok(self.slots.get(&(address, key)).copied().unwrap_or_default())
    }
}

impl MockDb {
    fn register(
        &mut self,
        index: u8,
        token: Address,
        mode: u8,
        decimals: u8,
        balance: FlaggedStorage,
    ) {
        self.slots.insert((GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT), U256::from(index + 1).into());
        self.slots.insert(
            (GAS_TOKEN_REGISTRY, token_metadata_slot(index)),
            (U256::from_be_slice(token.as_slice()) |
                (U256::from(1) << 160usize) |
                (U256::from(mode) << 168usize) |
                (U256::from(decimals) << 176usize))
                .into(),
        );
        self.slots
            .insert((GAS_TOKEN_REGISTRY, token_metadata_slot(index) + U256::from(1)), ROOT.into());
        self.slots.insert((token, balance_storage_key(CALLER, ROOT)), balance);
    }
}

fn tx(selector: GasPayment, price: u128, value: U256) -> SeismicTransaction<TxEnv> {
    SeismicTransaction::new(TxEnv {
        caller: CALLER,
        gas_price: price,
        value,
        tx_type: 74,
        ..Default::default()
    })
    .with_gas_payment(selector)
    .with_signed_read(true)
}

#[test]
fn allowance_matrix_every_precision_and_mode_matches_ceiling_affordability() {
    for decimals in 0..=18 {
        let precision = TokenPrecision::new(decimals).unwrap();
        for private in [false, true] {
            let mut db = MockDb::default();
            let raw = U256::from(7);
            db.register(0, TOKEN, u8::from(!private), decimals, FlaggedStorage::new(raw, private));
            for selector in [GasPayment::Auto, GasPayment::Token(TOKEN)] {
                for price in [1u128, 3, 1_000_000_000_001] {
                    let allowance =
                        caller_gas_allowance(&mut db, &tx(selector, price, U256::ZERO), u64::MAX)
                            .unwrap();
                    assert_eq!(
                        allowance,
                        precision.gas_allowance(raw, U256::from(price), u64::MAX).unwrap()
                    );
                    assert!(precision.ceil(U256::from(allowance) * U256::from(price)) <= raw);
                    if allowance < u64::MAX {
                        assert!(
                            precision.ceil(U256::from(allowance + 1) * U256::from(price)) > raw
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn auto_uses_largest_individual_capacity_not_sum_or_insertion_order() {
    let mut db = MockDb { native: U256::from(150), ..Default::default() };
    db.register(0, TOKEN, 1, 18, U256::from(100).into());
    db.register(1, OTHER, 1, 6, U256::from(1).into());
    let transaction = tx(GasPayment::Auto, 1, U256::from(50));
    assert_eq!(caller_gas_allowance(&mut db, &transaction, u64::MAX).unwrap(), 1_000_000_000_000);
    assert!(db.reads.contains(&(OTHER, balance_storage_key(CALLER, ROOT))));
    assert_eq!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::from(50)), u64::MAX)
            .unwrap(),
        100
    );
}

#[test]
fn native_never_reads_registry_even_when_insufficient_or_malformed() {
    let mut db = MockDb {
        native: U256::from(100),
        fail: Some((GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT)),
        ..Default::default()
    };
    assert_eq!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Native, 2, U256::from(20)), u64::MAX)
            .unwrap(),
        40
    );
    db.native = U256::from(20);
    assert_eq!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Native, 2, U256::from(20)), u64::MAX)
            .unwrap(),
        0
    );
    assert!(db.reads.is_empty());
}

#[test]
fn native_value_is_required_before_token_reads_and_failures_are_not_zero_balances() {
    let mut db = MockDb::default();
    db.register(0, TOKEN, 1, 18, U256::MAX.into());
    assert!(matches!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::from(1)), u64::MAX),
        Err(SeismicEthApiError::Eth(EthApiError::InvalidTransaction(
            RpcInvalidTransactionError::InsufficientFundsForTransfer
        )))
    ));
    assert!(db.reads.is_empty());
    db.fail_basic = true;
    assert!(matches!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Auto, 1, U256::ZERO), u64::MAX),
        Err(SeismicEthApiError::Eth(EthApiError::Internal(_)))
    ));
}

#[test]
fn explicit_lookup_reads_only_selected_balance_and_stops_at_match() {
    let mut db = MockDb { native: U256::MAX, ..Default::default() };
    db.register(0, OTHER, 255, 255, U256::MAX.into());
    db.register(1, TOKEN, 1, 18, U256::from(21).into());
    db.register(2, Address::repeat_byte(0x44), 1, 18, U256::MAX.into());
    db.fail = Some((GAS_TOKEN_REGISTRY, token_metadata_slot(2)));
    assert_eq!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::ZERO), 100).unwrap(),
        21
    );
    assert_eq!(
        db.reads,
        vec![
            (GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT),
            (GAS_TOKEN_REGISTRY, token_metadata_slot(0)),
            (GAS_TOKEN_REGISTRY, token_metadata_slot(1)),
            (GAS_TOKEN_REGISTRY, token_metadata_slot(1) + U256::from(1)),
            (TOKEN, balance_storage_key(CALLER, ROOT)),
        ]
    );
}

#[test]
fn auto_propagates_later_required_failures_even_after_reaching_cap() {
    for fail in [
        (GAS_TOKEN_REGISTRY, token_metadata_slot(1)),
        (GAS_TOKEN_REGISTRY, token_metadata_slot(1) + U256::from(1)),
        (OTHER, balance_storage_key(CALLER, ROOT)),
    ] {
        let mut db = MockDb { native: U256::MAX, ..Default::default() };
        db.register(0, TOKEN, 1, 18, U256::MAX.into());
        db.register(1, OTHER, 1, 18, U256::MAX.into());
        db.fail = Some(fail);
        let result = caller_gas_allowance(&mut db, &tx(GasPayment::Auto, 1, U256::ZERO), 100);
        assert!(matches!(result, Err(SeismicEthApiError::Eth(EthApiError::Internal(_)))));
    }
}

#[test]
fn ineligible_metadata_and_mode_mismatches_are_skipped_without_initialization() {
    let mut db = MockDb::default();
    db.register(0, TOKEN, 0, 18, U256::from(100).into()); // nonzero public in Shielded mode
    db.register(1, OTHER, 1, 19, U256::MAX.into());
    db.fail = Some((GAS_TOKEN_REGISTRY, token_metadata_slot(1) + U256::from(1)));
    let original = db.slots.clone();
    assert_eq!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Auto, 1, U256::ZERO), 100).unwrap(),
        0
    );
    assert!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::ZERO), 100).is_err()
    );
    assert!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Token(OTHER), 1, U256::ZERO), 100).is_err()
    );
    assert_eq!(db.slots, original);
}

#[test]
fn inactive_unsupported_unknown_and_zero_selected_tokens_fail_without_fallback() {
    for (active, mode, decimals) in [(0u8, 255u8, 255u8), (1, 2, 18), (1, 1, 19)] {
        let mut db = MockDb { native: U256::MAX, ..Default::default() };
        db.register(0, TOKEN, mode, decimals, U256::MAX.into());
        if active == 0 {
            db.slots.insert(
                (GAS_TOKEN_REGISTRY, token_metadata_slot(0)),
                U256::from_be_slice(TOKEN.as_slice()).into(),
            );
        }
        assert!(caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::ZERO), 100)
            .is_err());
        assert_eq!(db.reads.len(), 2); // count and selected metadata only
    }
    for token in [OTHER, Address::ZERO] {
        let mut db = MockDb { native: U256::MAX, ..Default::default() };
        db.register(0, TOKEN, 1, 18, U256::MAX.into());
        assert!(caller_gas_allowance(&mut db, &tx(GasPayment::Token(token), 1, U256::ZERO), 100)
            .is_err());
        assert!(db.reads.iter().all(|(address, _)| *address == GAS_TOKEN_REGISTRY));
    }
}

#[test]
fn required_reads_and_oversized_registry_have_distinct_error_channels() {
    for fail in [
        (GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT),
        (GAS_TOKEN_REGISTRY, token_metadata_slot(0)),
        (GAS_TOKEN_REGISTRY, token_metadata_slot(0) + U256::from(1)),
        (TOKEN, balance_storage_key(CALLER, ROOT)),
    ] {
        let mut db = MockDb::default();
        db.register(0, TOKEN, 1, 18, U256::from(100).into());
        db.fail = Some(fail);
        assert!(matches!(
            caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::ZERO), 100),
            Err(SeismicEthApiError::Eth(EthApiError::Internal(_)))
        ));
    }
    let mut db = MockDb::default();
    db.slots.insert((GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT), U256::from(33).into());
    assert!(matches!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Auto, 1, U256::ZERO), 100),
        Err(SeismicEthApiError::Eth(EthApiError::InvalidTransaction(_)))
    ));
}

#[test]
fn zero_public_shielded_and_missing_balances_are_eligible_read_only() {
    let mut db = MockDb::default();
    db.register(0, TOKEN, 0, 18, FlaggedStorage::default());
    for remove in [false, true] {
        if remove {
            db.slots.remove(&(TOKEN, balance_storage_key(CALLER, ROOT)));
        }
        assert_eq!(
            caller_gas_allowance(&mut db, &tx(GasPayment::Token(TOKEN), 1, U256::ZERO), 100)
                .unwrap(),
            0
        );
    }
}

#[test]
fn large_products_are_divided_before_capping_and_blob_fee_is_not_split() {
    let mut db = MockDb::default();
    db.register(0, TOKEN, 1, 0, U256::MAX.into());
    assert_eq!(
        caller_gas_allowance(
            &mut db,
            &tx(GasPayment::Token(TOKEN), u128::MAX, U256::ZERO),
            u64::MAX
        )
        .unwrap(),
        u64::MAX
    );
    assert_eq!(
        asset_allowance(
            U256::MAX,
            TokenPrecision::new(0).unwrap(),
            U256::ZERO,
            U256::MAX,
            u64::MAX
        ),
        1_000_000_000_000_000_000
    );

    db = MockDb { native: U256::from(262_143), ..Default::default() };
    db.register(0, TOKEN, 1, 18, U256::from(262_144).into());
    let mut blob = tx(GasPayment::Auto, 2, U256::from(1));
    blob.base.tx_type = 3;
    blob.base.max_fee_per_blob_gas = 2;
    blob.base.blob_hashes = vec![B256::repeat_byte(1)];
    assert_eq!(caller_gas_allowance(&mut db, &blob, 100).unwrap(), 0);
    db.slots.insert((TOKEN, balance_storage_key(CALLER, ROOT)), U256::from(262_164).into());
    assert_eq!(caller_gas_allowance(&mut db, &blob, 100).unwrap(), 10);
    blob.base.max_fee_per_blob_gas = u128::MAX;
    assert_eq!(caller_gas_allowance(&mut db, &blob, 100).unwrap(), 0);
}

#[test]
fn zero_price_preserves_estimator_flow_without_reads() {
    let mut db = MockDb { fail_basic: true, ..Default::default() };
    assert_eq!(
        caller_gas_allowance(&mut db, &tx(GasPayment::Token(OTHER), 0, U256::ZERO), 123).unwrap(),
        123
    );
    assert_eq!(db.basic_reads, 0);
    assert!(db.reads.is_empty());
}

#[test]
fn permitted_native_override_is_used_and_storage_overrides_stay_forbidden() {
    use alloy_rpc_types::state::{AccountOverride, StateOverride};
    use revm::database::InMemoryDB;
    let mut db = InMemoryDB::default();
    let transaction = tx(GasPayment::Native, 1, U256::from(20));
    reth_evm::overrides::apply_state_overrides(
        StateOverride::from_iter([(
            CALLER,
            AccountOverride { balance: Some(U256::from(120)), ..Default::default() },
        )]),
        &mut db,
    )
    .unwrap();
    assert_eq!(caller_gas_allowance(&mut db, &transaction, 1000).unwrap(), 100);
    let overrides = StateOverride::from_iter([(
        GAS_TOKEN_REGISTRY,
        AccountOverride {
            state_diff: Some(std::iter::once((B256::ZERO, B256::ZERO)).collect()),
            ..Default::default()
        },
    )]);
    assert!(reth_evm::overrides::apply_state_overrides(overrides, &mut db).is_err());
}

#[test]
fn simulated_block_snapshot_executes_plaintext_signed_reads_but_live_and_replay_do_not() {
    use alloy_consensus::{transaction::Recovered, SignableTransaction};
    use alloy_primitives::{Bytes, Signature, TxKind};
    use reth_evm::{
        block::BlockExecutorFactory, eth::EthBlockExecutionCtx, execute::BlockExecutor,
        ConfigureEvm,
    };
    use reth_seismic_evm::SeismicEvmConfig;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use revm::database::{InMemoryDB, State};
    use seismic_alloy_consensus::{TxSeismic, TxSeismicElements};
    use std::sync::Arc;
    let live = SeismicEvmConfig::new(
        reth_seismic_chainspec::SEISMIC_MAINNET.clone(),
        Arc::new(reth_seismic_keys::PurposeKeyring::single_epoch(
            alloy_seismic_evm::PurposeKeys::well_known(),
        )),
    );
    for (simulation, signed_read, expires, expected) in [
        (true, true, 0u64, Some(true)), // expiry already checked at tip, not simulated height
        (false, true, 1000, Some(false)), // live factory never treats plaintext as ciphertext
        (true, false, 1000, Some(false)), // ordinary encrypted replay keeps decryption
        (true, false, 0, None),         // replay keeps freshness validation too
    ] {
        let config = if simulation { live.snapshot_for_simulation() } else { live.clone() };
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            CALLER,
            AccountInfo { balance: U256::from(1_000_000), ..Default::default() },
        );
        db.insert_account_info(TOKEN, AccountInfo { nonce: 1, ..Default::default() });
        db.insert_account_info(GAS_TOKEN_REGISTRY, AccountInfo { nonce: 1, ..Default::default() });
        db.insert_account_info(
            OTHER,
            AccountInfo::from_bytecode(Bytecode::new_raw(Bytes::from_static(&[
                0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3,
            ]))),
        );
        let mut fixture = MockDb::default();
        fixture.register(0, TOKEN, 1, 18, U256::from(100_000).into());
        for ((address, key), value) in fixture.slots {
            db.insert_account_storage(address, key, value).unwrap();
        }
        let mut state = State::builder().with_database(db).build();
        let header = alloy_consensus::Header {
            number: 1,
            gas_limit: 1_000_000,
            excess_blob_gas: Some(0),
            ..Default::default()
        };
        let env = config.evm_env(&header);
        let evm = config.evm_with_env(&mut state, env);
        let context = EthBlockExecutionCtx {
            withdrawals: None,
            ommers: &[],
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
        };
        let mut executor = config.executor_factory.create_executor(evm, context);
        executor.apply_pre_execution_changes().unwrap();
        let transaction: SeismicTransactionSigned = TxSeismic {
            chain_id: reth_chainspec::EthChainSpec::chain_id(config.chain_spec().as_ref()),
            gas_price: 1,
            gas_limit: 30_000,
            to: TxKind::Call(OTHER),
            input: Bytes::from_static(b"plaintext"),
            gas_payment: seismic_alloy_consensus::GasPayment::Token(TOKEN),
            seismic_elements: TxSeismicElements {
                signed_read,
                expires_at_block: expires,
                ..Default::default()
            },
            ..Default::default()
        }
        .into_signed(Signature::new(U256::from(1), U256::from(2), false))
        .into();
        let mut success = None;
        let result = executor.execute_transaction_with_result_closure(
            Recovered::new_unchecked(transaction, CALLER),
            |result| {
                success = Some(result.is_success());
            },
        );
        if expected.is_none() {
            assert!(result.is_err());
        } else {
            result.unwrap();
        }
        assert_eq!(success, expected);
        let _ = executor.finish().unwrap();
        assert_eq!(state.basic(CALLER).unwrap().unwrap().balance, U256::from(1_000_000));
        if expected.is_some() {
            assert!(
                state.storage(TOKEN, balance_storage_key(CALLER, ROOT)).unwrap().value <
                    U256::from(100_000)
            );
        }
    }
}

#[test]
fn signed_request_conversion_and_simulation_use_the_exact_selected_token() {
    use crate::eth::SignableSeismicTransactionRequest;
    use reth_rpc_convert::transaction::TryIntoTxEnv;
    use revm::{database::InMemoryDB, Context, ExecuteEvm};
    use seismic_alloy_consensus::{TxSeismic, TxSeismicElements};
    use seismic_alloy_rpc_types::SeismicTransactionRequest;
    use seismic_revm::{DefaultSeismicContext, SeismicBuilder};

    let mut request: SeismicTransactionRequest = TxSeismic {
        gas_payment: seismic_alloy_consensus::GasPayment::Token(TOKEN),
        gas_limit: 30_000,
        gas_price: 1,
        to: alloy_primitives::TxKind::Call(OTHER),
        seismic_elements: TxSeismicElements { signed_read: true, ..Default::default() },
        ..Default::default()
    }
    .into();
    request.inner.from = Some(CALLER);
    let cfg = revm::context::CfgEnv::<seismic_revm::SeismicSpecId>::default();
    let block = revm::context::BlockEnv::default();
    let transaction =
        SignableSeismicTransactionRequest::from(request).try_into_tx_env(&cfg, &block).unwrap();
    assert_eq!(transaction.gas_payment, GasPayment::Token(TOKEN));
    assert!(transaction.signed_read);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        CALLER,
        AccountInfo { balance: U256::from(1_000_000), ..Default::default() },
    );
    db.insert_account_info(TOKEN, AccountInfo { nonce: 1, ..Default::default() });
    let mut fixture = MockDb::default();
    fixture.register(0, TOKEN, 1, 18, U256::from(100_000).into());
    for ((address, key), value) in fixture.slots {
        db.insert_account_storage(address, key, value).unwrap();
    }
    let mut evm = Context::seismic_with_rng_key([0; 64]).with_db(db).build_seismic_evm();
    let result = evm.transact(transaction).unwrap();
    assert!(result.result.is_success());
    assert_eq!(result.state[&CALLER].info.balance, U256::from(1_000_000));
    assert!(
        result.state[&TOKEN].storage[&balance_storage_key(CALLER, ROOT)].present_value.value <
            U256::from(100_000)
    );
    // Native can pay, but strict token selection still debits the token. The
    // transaction body has no code; this is not a simulation-only asset hint.
}
