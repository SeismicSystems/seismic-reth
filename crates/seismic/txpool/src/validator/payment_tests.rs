//! Selector admission, provider error, and snapshot regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::SeismicPooledTransaction;
use alloy_consensus::{
    transaction::Recovered, SignableTransaction, Transaction, TxEip4844, TxLegacy,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, FlaggedStorage, Signature, TxKind, B256, U256};
use reth_primitives_traits::{Account, Bytecode};
use reth_provider::{
    test_utils::{ExtendedAccount, MockEthProvider},
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, ProviderError,
    ProviderResult, StateProofProvider, StateRootProvider, StorageRootProvider,
};
use reth_seismic_chainspec::SEISMIC_MAINNET;
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder, BestTransactions,
    CoinbaseTipOrdering, Pool, PoolTransaction, TransactionPool,
};
use reth_trie_common::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm::{context::result::InvalidTransaction, database::BundleState};
use seismic_alloy_consensus::{GasPayment as SignedGasPayment, TxSeismic};
use seismic_revm::gas_token_registry::{
    balance_storage_key, token_metadata_slot, SelectedPayment, TokenPrecision, GAS_TOKEN_REGISTRY,
    TOKEN_COUNT_SLOT,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

const GAS_LIMIT: u64 = 100_000;
const GAS_PRICE: u128 = 10_000_000_000;
const GAS_COST: u128 = GAS_LIMIT as u128 * GAS_PRICE;

fn sender() -> Address {
    Address::with_last_byte(0x42)
}
fn token(n: u8) -> Address {
    Address::with_last_byte(n)
}
fn key(slot: U256) -> B256 {
    slot.to_be_bytes::<32>().into()
}
fn client(native: U256) -> MockEthProvider {
    let client = MockEthProvider::default().with_chain_spec(SEISMIC_MAINNET.inner().clone());
    client.add_account(sender(), ExtendedAccount::new(0, native));
    client
}

#[derive(Clone, Copy)]
struct Entry {
    address: Address,
    root: U256,
    active: bool,
    mode: u8,
    decimals: u8,
    balance: FlaggedStorage,
}

fn entry(address: Address, decimals: u8, balance: FlaggedStorage) -> Entry {
    // Deliberately use a mapping root whose significant bits exceed one byte.
    Entry {
        address,
        root: (U256::from(1) << 200usize) + U256::from(3),
        active: true,
        mode: 1,
        decimals,
        balance,
    }
}

fn seed(client: &MockEthProvider, entries: &[Entry]) {
    let mut storage =
        vec![(key(TOKEN_COUNT_SLOT), FlaggedStorage::public(U256::from(entries.len())))];
    for (index, entry) in entries.iter().enumerate() {
        let metadata = U256::from_be_slice(entry.address.as_slice()) |
            (U256::from(u8::from(entry.active)) << 160usize) |
            (U256::from(entry.mode) << 168usize) |
            (U256::from(entry.decimals) << 176usize);
        let slot = token_metadata_slot(u8::try_from(index).unwrap());
        storage.push((key(slot), FlaggedStorage::public(metadata)));
        storage.push((key(slot + U256::from(1)), FlaggedStorage::public(entry.root)));
        client.add_account(
            entry.address,
            ExtendedAccount::new(0, U256::ZERO)
                .extend_storage([(key(balance_storage_key(sender(), entry.root)), entry.balance)]),
        );
    }
    client.add_account(
        GAS_TOKEN_REGISTRY,
        ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
    );
}

fn validator(
    client: MockEthProvider,
) -> SeismicTransactionValidator<MockEthProvider, SeismicPooledTransaction> {
    SeismicTransactionValidator::new(
        EthTransactionValidatorBuilder::new(client)
            .no_shanghai()
            .no_cancun()
            .disable_balance_check()
            .build(InMemoryBlobStore::default()),
    )
}

fn pooled(selector: SignedGasPayment, value: U256) -> SeismicPooledTransaction {
    let mut tx = TxSeismic {
        chain_id: 5123,
        gas_limit: GAS_LIMIT,
        gas_price: GAS_PRICE,
        gas_payment: selector,
        value,
        to: TxKind::Call(token(0x43)),
        ..Default::default()
    };
    tx.seismic_elements.expires_at_block = u64::MAX;
    let signed: SeismicTransactionSigned =
        tx.into_signed(Signature::new(U256::from(1), U256::from(1), false)).into();
    let recovered = Recovered::new_unchecked(signed, sender());
    let len = recovered.encode_2718_len();
    SeismicPooledTransaction::new(recovered, len)
}

fn invalid(outcome: TransactionValidationOutcome<SeismicPooledTransaction>) -> InvalidTransaction {
    match outcome {
        TransactionValidationOutcome::Invalid(_, error) => error
            .downcast_other_ref::<SeismicPaymentError>()
            .expect("typed payment error")
            .reason()
            .clone(),
        other => panic!("expected deterministic invalidity, got: {other:?}"),
    }
}
fn valid_balance(outcome: TransactionValidationOutcome<SeismicPooledTransaction>) -> U256 {
    match outcome {
        TransactionValidationOutcome::Valid { balance, .. } => balance,
        other => panic!("expected valid admission, got: {other:?}"),
    }
}

/// Rebuild the cost/hash cache rather than mutating a pooled transaction in place.
fn with_nonce_and_price(
    selector: SignedGasPayment,
    nonce: u64,
    gas_price: u128,
) -> SeismicPooledTransaction {
    let original = pooled(selector, U256::ZERO).into_consensus();
    let SeismicTypedTransaction::Seismic(mut tx) = original.into_inner().into_parts().0 else {
        panic!("expected Seismic transaction")
    };
    tx.nonce = nonce;
    tx.gas_price = gas_price;
    let signed: SeismicTransactionSigned =
        tx.into_signed(Signature::new(U256::from(1), U256::from(1), false)).into();
    let encoded_length = signed.encode_2718_len();
    SeismicPooledTransaction::new(Recovered::new_unchecked(signed, sender()), encoded_length)
}

#[tokio::test]
async fn invalid_explicit_replacement_does_not_change_the_original_selector() {
    let state = client(U256::from(GAS_COST * 100));
    let pinned = token(0x44);
    seed(
        &state,
        &[
            entry(pinned, 18, FlaggedStorage::public(U256::ZERO)),
            entry(token(0x45), 18, FlaggedStorage::public(U256::from(GAS_COST * 100))),
        ],
    );
    let pool = Pool::new(
        validator(state),
        CoinbaseTipOrdering::default(),
        InMemoryBlobStore::default(),
        Default::default(),
    );
    let original = with_nonce_and_price(SignedGasPayment::Auto, 0, GAS_PRICE);
    let expected = original.clone_into_consensus();
    let original_hash = *original.hash();
    pool.add_transaction(TransactionOrigin::Local, original).await.unwrap();
    let replacement = with_nonce_and_price(SignedGasPayment::Token(pinned), 0, GAS_PRICE * 2);
    let replacement_hash = *replacement.hash();
    assert!(pool.add_transaction(TransactionOrigin::Local, replacement).await.is_err());
    assert!(pool.get(&replacement_hash).is_none());
    assert_eq!(pool.get(&original_hash).unwrap().to_consensus(), expected);
    assert_eq!(pool.best_transactions().next().unwrap().to_consensus(), expected);
}

#[tokio::test]
async fn replacement_pool_storage_and_payload_iterator_preserve_selectors() {
    let a = token(0x44);
    let b = token(0x45);
    for selector in [
        SignedGasPayment::Auto,
        SignedGasPayment::Native,
        SignedGasPayment::Token(a),
        SignedGasPayment::Token(b),
    ] {
        let state = client(U256::from(GAS_COST * 100));
        seed(
            &state,
            &[
                entry(a, 6, FlaggedStorage::public(U256::from(1_000_000))),
                entry(b, 18, FlaggedStorage::public(U256::from(GAS_COST * 100))),
            ],
        );
        let pool = Pool::new(
            validator(state),
            CoinbaseTipOrdering::default(),
            InMemoryBlobStore::default(),
            Default::default(),
        );
        let original = with_nonce_and_price(SignedGasPayment::Auto, 0, GAS_PRICE);
        let original_hash = *original.hash();
        pool.add_transaction(TransactionOrigin::Local, original).await.unwrap();
        let replacement = with_nonce_and_price(selector, 0, GAS_PRICE * 2);
        let expected = replacement.clone_into_consensus();
        let replacement_hash = *replacement.hash();
        pool.add_transaction(TransactionOrigin::Local, replacement).await.unwrap();
        assert!(pool.get(&original_hash).is_none());
        assert_eq!(pool.get(&replacement_hash).unwrap().to_consensus(), expected);
        assert_eq!(pool.get_local_transactions().len(), 1);
        assert_eq!(pool.get_local_transactions().first().unwrap().to_consensus(), expected);

        let descendant = with_nonce_and_price(SignedGasPayment::Token(b), 1, GAS_PRICE * 2);
        let descendant_hash = *descendant.hash();
        pool.add_transaction(TransactionOrigin::Local, descendant).await.unwrap();
        let mut best = pool.best_transactions();
        let selected = best.next().unwrap();
        assert_eq!(selected.to_consensus(), expected);
        assert_eq!(
            selected.transaction.clone().try_into_pooled().unwrap(),
            expected.clone().convert::<seismic_alloy_consensus::SeismicTxEnvelope>()
        );
        // Payload building marks a state-invalid transaction; dependent nonces must not
        // be selected, even when their signed selector points at another funded asset.
        best.mark_invalid(
            &selected,
            InvalidPoolTransactionError::other(SeismicPaymentError(
                InvalidTransaction::GasTokenInactive(a),
            )),
        );
        assert!(best.next().is_none());
        assert!(pool.get(&descendant_hash).is_some(), "iteration must not evict pool storage");
    }
}

#[tokio::test]
async fn mixed_precision_selector_affordability_boundaries() {
    for decimals in 0..=18 {
        for mode in [0, 1] {
            let precision = TokenPrecision::new(decimals).unwrap();
            let required = precision.ceil(U256::from(GAS_COST));
            for selector in [SignedGasPayment::Auto, SignedGasPayment::Token(token(0x44))] {
                for sufficient in [false, true] {
                    let native = U256::from(123);
                    let client = client(native);
                    let raw = required - U256::from(u8::from(!sufficient));
                    let mut candidate =
                        entry(token(0x44), decimals, FlaggedStorage::new(raw, mode == 0));
                    candidate.mode = mode;
                    seed(&client, &[candidate]);
                    let validator = validator(client);
                    let tx = pooled(selector, native);
                    let original = tx.clone_into_consensus();
                    let outcome =
                        validator.validate_transaction(TransactionOrigin::External, tx).await;
                    if sufficient {
                        match outcome {
                            TransactionValidationOutcome::Valid {
                                balance, transaction, ..
                            } => {
                                assert_eq!(balance, native + precision.aggregate(raw));
                                assert_eq!(
                                    transaction.transaction().clone_into_consensus(),
                                    original
                                );
                            }
                            other => panic!("expected funded selector, got: {other:?}"),
                        }
                    } else {
                        assert!(matches!(
                            invalid(outcome),
                            InvalidTransaction::LackOfFundForMaxFee { .. }
                        ));
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn explicit_selection_never_falls_back_to_native_or_other_token() {
    let client = client(U256::from(GAS_COST * 2));
    let a = entry(token(0x44), 18, FlaggedStorage::public(U256::from(GAS_COST - 1)));
    let b = entry(token(0x45), 6, FlaggedStorage::public(U256::from(1_000)));
    seed(&client, &[b, a]);
    let validator = validator(client);
    let pinned = pooled(SignedGasPayment::Token(a.address), U256::ZERO);
    assert!(matches!(
        invalid(validator.validate_transaction(TransactionOrigin::External, pinned).await),
        InvalidTransaction::LackOfFundForMaxFee { .. }
    ));
    let auto = pooled(SignedGasPayment::Auto, U256::ZERO);
    assert_eq!(
        valid_balance(validator.validate_transaction(TransactionOrigin::External, auto).await),
        U256::from(GAS_COST * 4 - 1)
    );
}

#[tokio::test]
async fn native_is_strict_and_fee_fragments_cannot_be_combined() {
    let client = client(U256::from(GAS_COST / 2));
    seed(
        &client,
        &[
            entry(token(0x44), 18, FlaggedStorage::public(U256::from(GAS_COST / 2))),
            entry(token(0x45), 18, FlaggedStorage::public(U256::from(GAS_COST / 2))),
        ],
    );
    let validator = validator(client);
    for selector in
        [SignedGasPayment::Auto, SignedGasPayment::Native, SignedGasPayment::Token(token(0x44))]
    {
        assert!(matches!(
            invalid(
                validator
                    .validate_transaction(TransactionOrigin::External, pooled(selector, U256::ZERO))
                    .await
            ),
            InvalidTransaction::LackOfFundForMaxFee { .. }
        ));
    }
}

#[tokio::test]
async fn original_value_is_always_native_funded_at_admission() {
    let client = client(U256::from(99));
    seed(&client, &[entry(token(0x44), 18, FlaggedStorage::private(U256::MAX))]);
    let validator = validator(client);
    for selector in
        [SignedGasPayment::Auto, SignedGasPayment::Native, SignedGasPayment::Token(token(0x44))]
    {
        let reason = invalid(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    pooled(selector, U256::from(100)),
                )
                .await,
        );
        assert_eq!(
            reason,
            InvalidTransaction::LackOfFundForMaxFee {
                fee: Box::new(U256::from(100)),
                balance: Box::new(U256::from(99))
            }
        );
    }
}

#[tokio::test]
async fn explicit_registry_errors_remain_typed() {
    let address = token(0x44);
    let base = entry(address, 6, FlaggedStorage::public(U256::from(1_000)));
    for (candidate, expected) in [
        (Entry { active: false, ..base }, InvalidTransaction::GasTokenInactive(address)),
        (
            Entry { mode: 2, ..base },
            InvalidTransaction::UnsupportedGasTokenMode { token: address, mode: 2 },
        ),
        (
            Entry { decimals: 19, ..base },
            InvalidTransaction::UnsupportedGasTokenDecimals { token: address, decimals: 19 },
        ),
        (
            Entry { balance: FlaggedStorage::private(U256::from(1_000)), ..base },
            InvalidTransaction::GasTokenBalanceModeMismatch { token: address, account: sender() },
        ),
        (
            Entry { mode: 0, ..base },
            InvalidTransaction::GasTokenBalanceModeMismatch { token: address, account: sender() },
        ),
    ] {
        let client = client(U256::from(GAS_COST));
        seed(&client, &[candidate]);
        let validator = validator(client);
        assert_eq!(
            invalid(
                validator
                    .validate_transaction(
                        TransactionOrigin::External,
                        pooled(SignedGasPayment::Token(address), U256::ZERO)
                    )
                    .await
            ),
            expected
        );
    }
    let validator = validator(client(U256::from(GAS_COST)));
    assert_eq!(
        invalid(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    pooled(SignedGasPayment::Token(address), U256::ZERO)
                )
                .await
        ),
        InvalidTransaction::GasTokenNotRegistered(address)
    );
    assert_eq!(
        invalid(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    pooled(SignedGasPayment::Token(Address::ZERO), U256::ZERO)
                )
                .await
        ),
        InvalidTransaction::InvalidGasPaymentSelector
    );
}

#[tokio::test]
async fn aggregate_omits_invalid_entries_and_scales_each_precision() {
    let client = client(U256::from(123));
    let base = entry(token(0x44), 6, FlaggedStorage::public(U256::from(1_000)));
    seed(
        &client,
        &[
            base,
            entry(token(0x45), 0, FlaggedStorage::public(U256::from(1))),
            entry(token(0x46), 8, FlaggedStorage::public(U256::from(100_000))),
            entry(token(0x47), 18, FlaggedStorage::public(U256::from(GAS_COST))),
            Entry { active: false, ..entry(token(0x48), 18, FlaggedStorage::public(U256::MAX)) },
            Entry { mode: 2, ..entry(token(0x49), 18, FlaggedStorage::public(U256::MAX)) },
            entry(token(0x50), 19, FlaggedStorage::public(U256::MAX)),
            entry(token(0x51), 18, FlaggedStorage::private(U256::MAX)),
            Entry { mode: 0, ..entry(token(0x52), 18, FlaggedStorage::public(U256::MAX)) },
        ],
    );
    let validator = validator(client);
    assert_eq!(
        valid_balance(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    pooled(SignedGasPayment::Auto, U256::ZERO)
                )
                .await
        ),
        U256::from(123) + U256::from(10u128.pow(18)) + U256::from(3 * GAS_COST)
    );
}

#[tokio::test]
async fn pool_aggregate_saturates_without_authorizing_a_fragmented_fee() {
    let client = client(U256::ZERO);
    seed(&client, &[entry(token(0x44), 0, FlaggedStorage::public(U256::MAX))]);
    let validator = validator(client);
    assert_eq!(
        valid_balance(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    pooled(SignedGasPayment::Token(token(0x44)), U256::ZERO)
                )
                .await
        ),
        U256::MAX
    );
}

#[test]
fn maximum_fee_includes_wide_blob_cost_without_saturation() {
    let tx = TxEip4844 {
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: GAS_PRICE,
        max_fee_per_blob_gas: u128::MAX,
        blob_versioned_hashes: vec![B256::repeat_byte(1)],
        ..Default::default()
    };
    let expected =
        U256::from(GAS_COST) + U256::from(u128::MAX) * U256::from(tx.blob_gas_used().unwrap());
    assert!(expected > U256::from(u128::MAX));
    assert_eq!(maximum_gas_cost(&tx), Ok(expected));
}

#[tokio::test]
async fn overflowing_value_plus_fee_is_invalid_even_if_pool_cost_saturates() {
    let client = client(U256::MAX);
    let validator = validator(client);
    for selector in
        [SignedGasPayment::Auto, SignedGasPayment::Native, SignedGasPayment::Token(token(0x44))]
    {
        let tx = pooled(selector, U256::MAX);
        assert_eq!(*tx.cost(), U256::MAX);
        assert_eq!(
            invalid(validator.validate_transaction(TransactionOrigin::External, tx).await),
            InvalidTransaction::OverflowPaymentInTransaction
        );
    }
}

#[tokio::test]
async fn standard_transactions_use_registered_auto_payment() {
    let client = client(U256::ZERO);
    seed(&client, &[entry(token(0x44), 6, FlaggedStorage::public(U256::from(1_000)))]);
    let tx = TxLegacy {
        chain_id: Some(5123),
        gas_limit: GAS_LIMIT,
        gas_price: GAS_PRICE,
        to: TxKind::Call(token(0x43)),
        ..Default::default()
    };
    let signed: SeismicTransactionSigned =
        tx.into_signed(Signature::new(U256::from(1), U256::from(1), false)).into();
    let recovered = Recovered::new_unchecked(signed, sender());
    let len = recovered.encode_2718_len();
    let validator = validator(client);
    assert_eq!(
        valid_balance(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    SeismicPooledTransaction::new(recovered, len)
                )
                .await
        ),
        U256::from(GAS_COST)
    );
}

/// Instrument one supplied snapshot independently of the client's latest state.
/// Unsupported trie APIs return errors so unexpected calls cannot quietly pass.
struct ObservedState {
    inner: MockEthProvider,
    fail_storage: Option<(Address, B256)>,
    fail_account: bool,
    fail_bytecode: bool,
    account_reads: AtomicUsize,
    bytecode_reads: AtomicUsize,
    storage_reads: Mutex<Vec<(Address, B256)>>,
}
impl ObservedState {
    fn new(inner: MockEthProvider) -> Self {
        Self {
            inner,
            fail_storage: None,
            fail_account: false,
            fail_bytecode: false,
            account_reads: AtomicUsize::new(0),
            bytecode_reads: AtomicUsize::new(0),
            storage_reads: Mutex::new(Vec::new()),
        }
    }
}
impl AccountReader for ObservedState {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.account_reads.fetch_add(1, Ordering::Relaxed);
        if self.fail_account {
            return Err(ProviderError::InvalidStorageOutput);
        }
        self.inner.basic_account(address)
    }
}
impl BytecodeReader for ObservedState {
    fn bytecode_by_hash(&self, hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.bytecode_reads.fetch_add(1, Ordering::Relaxed);
        if self.fail_bytecode {
            return Err(ProviderError::InvalidStorageOutput);
        }
        self.inner.bytecode_by_hash(hash)
    }
}
impl StateProvider for ObservedState {
    fn storage(&self, account: Address, slot: B256) -> ProviderResult<Option<FlaggedStorage>> {
        self.storage_reads.lock().unwrap().push((account, slot));
        if self.fail_storage == Some((account, slot)) {
            return Err(ProviderError::InvalidStorageOutput);
        }
        self.inner.storage(account, slot)
    }
}
impl BlockHashReader for ObservedState {
    fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn canonical_hashes_range(&self, _start: u64, _end: u64) -> ProviderResult<Vec<B256>> {
        Err(ProviderError::UnsupportedProvider)
    }
}
impl StateRootProvider for ObservedState {
    fn state_root(&self, _state: HashedPostState) -> ProviderResult<B256> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn state_root_with_updates(
        &self,
        _state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn state_root_from_nodes_with_updates(
        &self,
        _input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Err(ProviderError::UnsupportedProvider)
    }
}
impl StorageRootProvider for ObservedState {
    fn storage_root(&self, _address: Address, _storage: HashedStorage) -> ProviderResult<B256> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn storage_proof(
        &self,
        _address: Address,
        _slot: B256,
        _storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn storage_multiproof(
        &self,
        _address: Address,
        _slots: &[B256],
        _storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        Err(ProviderError::UnsupportedProvider)
    }
}
impl StateProofProvider for ObservedState {
    fn proof(
        &self,
        _input: TrieInput,
        _address: Address,
        _slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn multiproof(
        &self,
        _input: TrieInput,
        _targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn witness(&self, _input: TrieInput, _target: HashedPostState) -> ProviderResult<Vec<Bytes>> {
        Err(ProviderError::UnsupportedProvider)
    }
}
impl HashedPostStateProvider for ObservedState {
    fn hashed_post_state(&self, _state: &BundleState) -> HashedPostState {
        HashedPostState::default()
    }
}

#[test]
fn account_nonce_and_token_reads_use_the_supplied_snapshot_not_client_latest() {
    // Client latest is deliberately incompatible: nonce 7, no native balance,
    // no registered tokens. The supplied snapshot has nonce 0 and funds both.
    let latest = client(U256::ZERO);
    latest.add_account(sender(), ExtendedAccount::new(7, U256::ZERO));
    let snapshot = client(U256::from(123));
    let candidate = entry(token(0x44), 6, FlaggedStorage::public(U256::from(1_000)));
    seed(&snapshot, &[candidate]);
    let state = Arc::new(ObservedState::new(snapshot));
    let validator = validator(latest);
    let outcome = validator.validate_with_state(
        TransactionOrigin::External,
        pooled(SignedGasPayment::Token(candidate.address), U256::from(123)),
        state.clone(),
    );
    match outcome {
        TransactionValidationOutcome::Valid { balance, state_nonce, .. } => {
            assert_eq!(state_nonce, 0);
            assert_eq!(balance, U256::from(123 + GAS_COST));
        }
        other => panic!("wrong admission snapshot: {other:?}"),
    }
    assert_eq!(state.account_reads.load(Ordering::Relaxed), 1);
    assert!(state
        .storage_reads
        .lock()
        .unwrap()
        .contains(&(candidate.address, key(balance_storage_key(sender(), candidate.root)))));
}

#[test]
fn required_provider_failures_remain_errors() {
    let candidate = entry(token(0x44), 6, FlaggedStorage::public(U256::from(1_000)));
    for failure in [
        (GAS_TOKEN_REGISTRY, key(TOKEN_COUNT_SLOT)),
        (GAS_TOKEN_REGISTRY, key(token_metadata_slot(0))),
        (GAS_TOKEN_REGISTRY, key(token_metadata_slot(0) + U256::from(1))),
        (candidate.address, key(balance_storage_key(sender(), candidate.root))),
    ] {
        let snapshot = client(U256::ZERO);
        seed(&snapshot, &[candidate]);
        let mut state = ObservedState::new(snapshot);
        state.fail_storage = Some(failure);
        let state = Arc::new(state);
        let validator = validator(client(U256::ZERO));
        for selector in [SignedGasPayment::Auto, SignedGasPayment::Token(candidate.address)] {
            let tx = pooled(selector, U256::ZERO);
            let hash = *tx.hash();
            let outcome =
                validator.validate_with_state(TransactionOrigin::External, tx, state.clone());
            match outcome {
                TransactionValidationOutcome::Error(actual_hash, error) => {
                    assert_eq!(actual_hash, hash);
                    assert!(matches!(
                        error.downcast_ref::<ProviderError>(),
                        Some(ProviderError::InvalidStorageOutput)
                    ));
                }
                other => panic!("provider failure must not become invalidity: {other:?}"),
            }
        }
    }
    let mut state = ObservedState::new(client(U256::from(GAS_COST)));
    state.fail_account = true;
    let validator = validator(client(U256::ZERO));
    assert!(matches!(
        validator.validate_with_state(
            TransactionOrigin::External,
            pooled(SignedGasPayment::Native, U256::ZERO),
            Arc::new(state)
        ),
        TransactionValidationOutcome::Error(..)
    ));
}

#[test]
fn sender_code_is_validated_from_the_same_snapshot_and_read_errors_propagate() {
    // Under Prague, the Ethereum validator reads delegation code by hash.
    let snapshot = client(U256::from(GAS_COST));
    let delegation = revm::state::Bytecode::new_eip7702(token(0x43));
    snapshot.add_account(
        sender(),
        ExtendedAccount::new(0, U256::from(GAS_COST)).with_bytecode(delegation.original_bytes()),
    );
    let latest = client(U256::ZERO);
    // If sender code were read from client latest, the delegation would be absent.
    latest.add_account(
        sender(),
        ExtendedAccount::new(7, U256::ZERO).with_bytecode(Bytes::from_static(&[0x00])),
    );
    let validator = SeismicTransactionValidator::new(
        EthTransactionValidatorBuilder::new(latest)
            .disable_balance_check()
            .build(InMemoryBlobStore::default()),
    );
    let state = Arc::new(ObservedState::new(snapshot.clone()));
    valid_balance(validator.validate_with_state(
        TransactionOrigin::External,
        pooled(SignedGasPayment::Native, U256::ZERO),
        state.clone(),
    ));
    assert_eq!(state.account_reads.load(Ordering::Relaxed), 1);
    assert_eq!(state.bytecode_reads.load(Ordering::Relaxed), 1);
    let mut state = ObservedState::new(snapshot);
    state.fail_bytecode = true;
    let outcome = validator.validate_with_state(
        TransactionOrigin::External,
        pooled(SignedGasPayment::Native, U256::ZERO),
        Arc::new(state),
    );
    assert!(matches!(outcome, TransactionValidationOutcome::Error(..)));
}

#[test]
fn invalid_native_selection_does_not_read_registry_or_accept_affordable_tokens() {
    let snapshot = client(U256::from(GAS_COST - 1));
    seed(&snapshot, &[entry(token(0x44), 18, FlaggedStorage::public(U256::MAX))]);
    let state = Arc::new(ObservedState::new(snapshot));
    let validator = validator(client(U256::ZERO));
    assert!(matches!(
        invalid(validator.validate_with_state(
            TransactionOrigin::External,
            pooled(SignedGasPayment::Native, U256::ZERO),
            state.clone(),
        )),
        InvalidTransaction::LackOfFundForMaxFee { .. }
    ));
    assert!(state.storage_reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn shielded_zero_public_balance_is_eligible_when_maximum_fee_is_zero() {
    let client = client(U256::ZERO);
    let candidate = Entry { mode: 0, ..entry(token(0x44), 0, FlaggedStorage::public(U256::ZERO)) };
    seed(&client, &[candidate]);
    let mut tx = TxSeismic {
        chain_id: 5123,
        gas_limit: GAS_LIMIT,
        gas_price: 0,
        gas_payment: SignedGasPayment::Token(candidate.address),
        to: TxKind::Call(token(0x43)),
        ..Default::default()
    };
    tx.seismic_elements.expires_at_block = u64::MAX;
    let signed: SeismicTransactionSigned =
        tx.into_signed(Signature::new(U256::from(1), U256::from(1), false)).into();
    let recovered = Recovered::new_unchecked(signed, sender());
    let len = recovered.encode_2718_len();
    let validator = validator(client);
    assert_eq!(
        valid_balance(
            validator
                .validate_transaction(
                    TransactionOrigin::External,
                    SeismicPooledTransaction::new(recovered, len),
                )
                .await
        ),
        U256::ZERO
    );
}

#[test]
fn native_exact_selection_reads_nothing_but_pool_aggregate_errors_still_propagate() {
    let mut state = ObservedState::new(client(U256::from(GAS_COST)));
    state.fail_storage = Some((GAS_TOKEN_REGISTRY, key(TOKEN_COUNT_SLOT)));
    let state = Arc::new(state);
    for selector in [GasPayment::Auto, GasPayment::Native] {
        let mut reader = ProviderRegistryStorage(state.as_ref());
        assert_eq!(
            select_payment(
                &mut reader,
                selector,
                sender(),
                U256::from(GAS_COST),
                U256::ZERO,
                U256::from(GAS_COST)
            )
            .unwrap(),
            SelectedPayment::Native
        );
    }
    assert!(state.storage_reads.lock().unwrap().is_empty());
    let validator = validator(client(U256::ZERO));
    assert!(matches!(
        validator.validate_with_state(
            TransactionOrigin::External,
            pooled(SignedGasPayment::Native, U256::ZERO),
            state
        ),
        TransactionValidationOutcome::Error(..)
    ));
}

#[test]
fn exact_selection_is_lazy_but_admission_requires_complete_aggregate() {
    let snapshot = client(U256::ZERO);
    let a = entry(token(0x44), 6, FlaggedStorage::public(U256::from(1_000)));
    let b = entry(token(0x45), 18, FlaggedStorage::public(U256::from(GAS_COST)));
    seed(&snapshot, &[a, b]);
    let mut state = ObservedState::new(snapshot);
    state.fail_storage = Some((b.address, key(balance_storage_key(sender(), b.root))));
    let state = Arc::new(state);
    for selector in [GasPayment::Auto, GasPayment::Token(a.address)] {
        let mut reader = ProviderRegistryStorage(state.as_ref());
        assert!(
            matches!(select_payment(&mut reader, selector, sender(), U256::ZERO, U256::ZERO, U256::from(GAS_COST)), Ok(SelectedPayment::Token(selected)) if selected.token == a.address)
        );
    }
    assert!(!state.storage_reads.lock().unwrap().contains(&state.fail_storage.unwrap()));
    let validator = validator(client(U256::ZERO));
    assert!(matches!(
        validator.validate_with_state(
            TransactionOrigin::External,
            pooled(SignedGasPayment::Token(a.address), U256::ZERO),
            state
        ),
        TransactionValidationOutcome::Error(..)
    ));
}

#[test]
fn absent_slots_are_zero_public_but_privacy_flags_are_not_discarded() {
    let snapshot = client(U256::ZERO);
    let mut reader = ProviderRegistryStorage(&snapshot);
    assert_eq!(
        seismic_revm::gas_token_registry::RegistryStorage::read_storage(
            &mut reader,
            token(0x44),
            U256::from(1)
        )
        .unwrap(),
        FlaggedStorage::public(U256::ZERO)
    );
    let candidate = entry(token(0x44), 6, FlaggedStorage::private(U256::from(1_000)));
    seed(&snapshot, &[candidate]);
    assert_eq!(
        seismic_revm::gas_token_registry::RegistryStorage::read_storage(
            &mut reader,
            candidate.address,
            balance_storage_key(sender(), candidate.root)
        )
        .unwrap(),
        candidate.balance
    );
}
