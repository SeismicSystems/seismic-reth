//! Registry aggregates, lazy configuration-only discovery, and maintenance read failures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::{SeismicPaymentError, SeismicTransactionValidator};
use alloy_consensus::{transaction::Recovered, SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, FlaggedStorage, Signature, TxKind, B256, U256};
use reth_execution_types::{Chain, ExecutionOutcome};
use reth_primitives_traits::{Account, Block as _, Bytecode};
use reth_provider::{
    test_utils::{ExtendedAccount, MockEthProvider},
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, ProviderError,
    ProviderResult, StateProofProvider, StateRootProvider, StorageRootProvider,
};
use reth_seismic_chainspec::{SeismicChainSpec, SEISMIC_MAINNET};

/// Mock provider over the Seismic primitives and chain spec.
type SeismicMockProvider = MockEthProvider<SeismicPrimitives, SeismicChainSpec>;

fn seismic_mock_provider() -> SeismicMockProvider {
    MockEthProvider::<SeismicPrimitives, reth_chainspec::ChainSpec>::new()
        .with_chain_spec(SEISMIC_MAINNET.as_ref().clone())
}
use reth_seismic_primitives::{
    SeismicBlock, SeismicBlockBody, SeismicReceipt, SeismicTransactionSigned,
};
use reth_tasks::TaskManager;
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, maintain::maintain_transaction_pool_with_hook,
    validate::EthTransactionValidatorBuilder, CoinbaseTipOrdering, Pool, TransactionOrigin,
    TransactionPoolExt,
};
use reth_trie_common::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm::{context::result::InvalidTransaction, database::BundleState};
use seismic_revm::gas_token_registry::{token_metadata_slot, TokenPrecision, TOKEN_COUNT_SLOT};
use std::{collections::HashMap, sync::Mutex, time::Duration};

struct TestState {
    inner: SeismicMockProvider,
    failed_storage: Option<(Address, B256)>,
    storage_reads: Mutex<Vec<(Address, B256)>>,
}

impl Default for TestState {
    fn default() -> Self {
        Self {
            inner: seismic_mock_provider(),
            failed_storage: None,
            storage_reads: Mutex::new(Vec::new()),
        }
    }
}

impl AccountReader for TestState {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.inner.basic_account(address)
    }
}

impl BytecodeReader for TestState {
    fn bytecode_by_hash(&self, hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(hash)
    }
}

impl StateProvider for TestState {
    fn storage(&self, account: Address, slot: B256) -> ProviderResult<Option<FlaggedStorage>> {
        self.storage_reads.lock().unwrap().push((account, slot));
        if self.failed_storage == Some((account, slot)) {
            return Err(ProviderError::InvalidStorageOutput)
        }
        self.inner.storage(account, slot)
    }
}

// Unrelated APIs deliberately fail, so accidental extra reads do not pass silently.
impl BlockHashReader for TestState {
    fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn canonical_hashes_range(&self, _start: u64, _end: u64) -> ProviderResult<Vec<B256>> {
        Err(ProviderError::UnsupportedProvider)
    }
}

impl StateRootProvider for TestState {
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

impl StorageRootProvider for TestState {
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

impl StateProofProvider for TestState {
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

impl HashedPostStateProvider for TestState {
    fn hashed_post_state(&self, _state: &BundleState) -> HashedPostState {
        HashedPostState::default()
    }
}

fn accounts() -> Vec<ChangedAccount> {
    vec![
        ChangedAccount { address: Address::with_last_byte(1), nonce: 7, balance: U256::from(10) },
        ChangedAccount { address: Address::with_last_byte(2), nonce: 9, balance: U256::from(20) },
    ]
}

#[derive(Clone, Copy)]
struct Entry {
    token: Address,
    root: U256,
    mode: u8,
    decimals: u8,
    active: bool,
}

fn entry(index: u8, decimals: u8, mode: u8) -> Entry {
    Entry {
        token: Address::with_last_byte(0x40 + index),
        root: (U256::from(1) << 200usize) + U256::from(index),
        mode,
        decimals,
        active: true,
    }
}

fn key(slot: U256) -> B256 {
    slot.to_be_bytes::<32>().into()
}

fn seed_registry(state: &TestState, entries: &[Entry]) {
    let mut storage =
        vec![(key(TOKEN_COUNT_SLOT), FlaggedStorage::public(U256::from(entries.len())))];
    for (index, token) in entries.iter().enumerate() {
        let slot = token_metadata_slot(u8::try_from(index).unwrap());
        let word = U256::from_be_slice(token.token.as_slice()) |
            (U256::from(u8::from(token.active)) << 160usize) |
            (U256::from(token.mode) << 168usize) |
            (U256::from(token.decimals) << 176usize);
        storage.push((key(slot), FlaggedStorage::public(word)));
        storage.push((key(slot + U256::from(1)), FlaggedStorage::public(token.root)));
    }
    state.inner.add_account(
        GAS_TOKEN_REGISTRY,
        ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
    );
}

fn seed_balances(state: &TestState, token: Entry, balances: &[(Address, FlaggedStorage)]) {
    let storage = balances
        .iter()
        .map(|&(holder, balance)| (key(balance_storage_key(holder, token.root)), balance))
        .collect::<Vec<_>>();
    state
        .inner
        .add_account(token.token, ExtendedAccount::new(0, U256::ZERO).extend_storage(storage));
}

#[derive(Default)]
struct Changes {
    slots: HashMap<Address, HashSet<U256>>,
    wiped: HashSet<Address>,
}

impl Changes {
    fn slot(&mut self, address: Address, key: U256) {
        self.slots.entry(address).or_default().insert(key);
    }
}

impl CanonicalStorageChanges for Changes {
    fn has_storage_changes(&self) -> bool {
        !self.slots.is_empty() || !self.wiped.is_empty()
    }

    fn storage_changed(&self, address: Address) -> bool {
        self.slots.contains_key(&address) || self.wiped.contains(&address)
    }

    fn slot_changed(&self, address: Address, key: U256) -> bool {
        self.wiped.contains(&address) ||
            self.slots.get(&address).is_some_and(|keys| keys.contains(&key))
    }
}

#[test]
fn absent_registered_balance_is_successful_zero_not_a_provider_error() {
    let state = TestState::default();
    seed_registry(&state, &[entry(0, 6, 1)]);
    let mut records = accounts();
    let original = records.clone();
    SeismicBalanceHook.transform(&state, &mut records).unwrap();
    assert_eq!(records, original);
}

#[test]
fn maintenance_matches_shared_admission_aggregate_at_every_precision_and_mode() {
    for decimals in 0..=18 {
        for mode in 0..=1 {
            let state = TestState::default();
            let token = entry(0, decimals, mode);
            seed_registry(&state, &[token]);
            let mut records = accounts();
            let balances = records
                .iter()
                .map(|account| (account.address, FlaggedStorage::new(U256::from(5), mode == 0)))
                .collect::<Vec<_>>();
            seed_balances(&state, token, &balances);
            let expected = records
                .iter()
                .map(|account| {
                    let aggregate = aggregate_balance(
                        &mut ProviderRegistryStorage(&state),
                        account.address,
                        account.balance,
                    )
                    .unwrap();
                    ChangedAccount { balance: aggregate, ..*account }
                })
                .collect::<Vec<_>>();
            SeismicBalanceHook.transform(&state, &mut records).unwrap();
            assert_eq!(records, expected);
            for (updated, native) in records.iter().zip(accounts()) {
                assert_eq!(
                    updated.balance,
                    native.balance +
                        TokenPrecision::new(decimals).unwrap().aggregate(U256::from(5))
                );
            }
        }
    }
}

#[test]
fn mixed_precision_aggregate_omits_inactive_unsupported_and_incompatible_balances() {
    let state = TestState::default();
    let entries = [
        entry(0, 0, 1),
        entry(1, 6, 0),
        entry(2, 8, 1),
        entry(3, 18, 1),
        Entry { active: false, ..entry(4, 6, 1) },
        entry(5, 19, 1),
        entry(6, 6, 2),
        entry(7, 6, 0),
        entry(8, 6, 1),
    ];
    seed_registry(&state, &entries);
    let holder = Address::with_last_byte(1);
    for token in entries {
        let private = token.mode == 0 && token.token != entry(7, 6, 0).token ||
            token.token == entry(8, 6, 1).token;
        seed_balances(&state, token, &[(holder, FlaggedStorage::new(U256::from(5), private))]);
    }
    let mut records = vec![ChangedAccount { address: holder, nonce: 7, balance: U256::from(10) }];
    SeismicBalanceHook.transform(&state, &mut records).unwrap();
    let expected = [0, 6, 8, 18].into_iter().fold(U256::from(10), |total, decimals| {
        total + TokenPrecision::new(decimals).unwrap().aggregate(U256::from(5))
    });
    assert_eq!(records.first().unwrap().balance, expected);
}

#[test]
fn aggregate_saturates_without_changing_native_nonce_or_address() {
    let state = TestState::default();
    let token = entry(0, 0, 1);
    seed_registry(&state, &[token]);
    let original = accounts().remove(0);
    seed_balances(&state, token, &[(original.address, FlaggedStorage::public(U256::MAX))]);
    let mut records = vec![original];
    SeismicBalanceHook.transform(&state, &mut records).unwrap();
    assert_eq!(records, vec![ChangedAccount { balance: U256::MAX, ..original }]);
}

#[test]
fn later_holder_balance_read_failure_leaves_the_whole_batch_unchanged_and_can_retry() {
    let mut state = TestState::default();
    let token = entry(0, 6, 1);
    seed_registry(&state, &[token]);
    let original = accounts();
    seed_balances(
        &state,
        token,
        &original
            .iter()
            .map(|account| (account.address, FlaggedStorage::public(U256::from(5))))
            .collect::<Vec<_>>(),
    );
    state.failed_storage =
        Some((token.token, key(balance_storage_key(Address::with_last_byte(2), token.root))));
    let mut records = original.clone();
    assert!(matches!(
        SeismicBalanceHook.transform(&state, &mut records),
        Err(SeismicBalanceError::Provider(ProviderError::InvalidStorageOutput))
    ));
    assert_eq!(records, original);

    state.failed_storage = None;
    SeismicBalanceHook.transform(&state, &mut records).unwrap();
    for (updated, native) in records.iter().zip(original) {
        assert_eq!(updated.address, native.address);
        assert_eq!(updated.nonce, native.nonce);
        assert_eq!(
            updated.balance,
            native.balance + TokenPrecision::new(6).unwrap().aggregate(U256::from(5))
        );
    }
}

#[test]
fn oversized_registry_is_a_typed_refresh_error_not_a_fabricated_balance() {
    let state = TestState::default();
    state.inner.add_account(
        GAS_TOKEN_REGISTRY,
        ExtendedAccount::new(0, U256::ZERO)
            .extend_storage([(key(TOKEN_COUNT_SLOT), FlaggedStorage::public(U256::from(33)))]),
    );
    let mut records = accounts();
    let original = records.clone();
    let error = SeismicBalanceHook.transform(&state, &mut records).unwrap_err();
    assert!(
        matches!(&error, SeismicBalanceError::Registry(error) if error.reason() == &InvalidTransaction::GasTokenRegistryTooLarge)
    );
    assert_eq!(records, original);
}

#[test]
fn discovery_matches_full_width_balance_keys_without_reading_holder_balances() {
    let mut state = TestState::default();
    let a = entry(0, 6, 0);
    let b = entry(1, 18, 1);
    seed_registry(&state, &[a, b]);
    let alice = Address::with_last_byte(1);
    let bob = Address::with_last_byte(2);
    let pooled = HashSet::from([alice, bob]);
    let mut changes = Changes::default();
    changes.slot(a.token, balance_storage_key(alice, a.root));
    changes.slot(b.token, balance_storage_key(Address::with_last_byte(3), b.root));
    // An error at Alice's balance must not affect configuration-only discovery.
    state.failed_storage = Some((a.token, key(balance_storage_key(alice, a.root))));
    assert_eq!(
        SeismicBalanceHook.affected_accounts(&state, &changes, &pooled).unwrap(),
        HashSet::from([alice])
    );
    assert!(state
        .storage_reads
        .lock()
        .unwrap()
        .iter()
        .all(|&(address, _)| address == GAS_TOKEN_REGISTRY));
}

#[test]
fn registry_storage_mutation_refreshes_all_pooled_senders_without_discovery_reads() {
    let state = TestState::default();
    let pooled = HashSet::from([Address::with_last_byte(1), Address::with_last_byte(2)]);
    let mut changes = Changes::default();
    changes.slot(GAS_TOKEN_REGISTRY, token_metadata_slot(0));
    assert_eq!(SeismicBalanceHook.affected_accounts(&state, &changes, &pooled).unwrap(), pooled);
    assert!(state.storage_reads.lock().unwrap().is_empty());
}

#[test]
fn token_storage_wipe_refreshes_all_pooled_holders_of_that_token() {
    let state = TestState::default();
    let token = entry(0, 6, 1);
    seed_registry(&state, &[token]);
    let pooled = HashSet::from([Address::with_last_byte(1), Address::with_last_byte(2)]);
    let mut changes = Changes::default();
    changes.wiped.insert(token.token);
    assert_eq!(SeismicBalanceHook.affected_accounts(&state, &changes, &pooled).unwrap(), pooled);
}

#[test]
fn no_storage_changes_or_no_pooled_senders_require_no_registry_reads() {
    let state = TestState::default();
    let pooled = HashSet::from([Address::with_last_byte(1)]);
    assert!(SeismicBalanceHook
        .affected_accounts(&state, &Changes::default(), &pooled)
        .unwrap()
        .is_empty());
    let mut changes = Changes::default();
    changes.slot(GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT);
    assert!(SeismicBalanceHook
        .affected_accounts(&state, &changes, &HashSet::new())
        .unwrap()
        .is_empty());
    assert!(state.storage_reads.lock().unwrap().is_empty());
}

#[test]
fn unrelated_storage_changes_do_not_read_holder_balances() {
    let state = TestState::default();
    seed_registry(&state, &[entry(0, 6, 1)]);
    let pooled = HashSet::from([Address::with_last_byte(1)]);
    let mut changes = Changes::default();
    changes.slot(Address::with_last_byte(0xff), U256::from(7));
    assert!(SeismicBalanceHook.affected_accounts(&state, &changes, &pooled).unwrap().is_empty());
    assert!(state
        .storage_reads
        .lock()
        .unwrap()
        .iter()
        .all(|&(address, _)| address == GAS_TOKEN_REGISTRY));
}

#[test]
fn discovery_registry_read_failure_propagates_instead_of_reporting_no_affected_senders() {
    let state = TestState {
        failed_storage: Some((GAS_TOKEN_REGISTRY, key(TOKEN_COUNT_SLOT))),
        ..Default::default()
    };
    let mut changes = Changes::default();
    changes.slot(Address::with_last_byte(0x40), U256::from(7));
    let pooled = HashSet::from([Address::with_last_byte(1)]);
    assert!(matches!(
        SeismicBalanceHook.affected_accounts(&state, &changes, &pooled),
        Err(SeismicBalanceError::Provider(ProviderError::InvalidStorageOutput))
    ));
}

#[derive(Clone, Copy)]
enum RefreshCase {
    TokenDecrease,
    TokenIncrease,
    TokenReorg,
    RegistryDeactivate,
    RegistryReorg,
}

struct ObservedHook {
    discovered: Arc<Mutex<HashSet<Address>>>,
}

impl ChangedAccountsHook for ObservedHook {
    type Error = SeismicBalanceError;

    fn affected_accounts(
        &self,
        state: &dyn StateProvider,
        changes: &dyn CanonicalStorageChanges,
        pooled: &HashSet<Address>,
    ) -> Result<HashSet<Address>, Self::Error> {
        let affected = SeismicBalanceHook.affected_accounts(state, changes, pooled)?;
        self.discovered.lock().unwrap().extend(affected.iter().copied());
        Ok(affected)
    }

    fn transform(
        &self,
        state: &dyn StateProvider,
        records: &mut [ChangedAccount],
    ) -> Result<(), Self::Error> {
        SeismicBalanceHook.transform(state, records)
    }
}

fn pooled_legacy(sender: Address, nonce: u64) -> SeismicPooledTransaction {
    let tx = TxLegacy {
        chain_id: Some(5123),
        nonce,
        gas_limit: 21_000,
        gas_price: 10_000_000_000,
        // Unchecked fixture signers still need distinct signed transaction hashes.
        to: TxKind::Call(sender),
        ..Default::default()
    };
    let signed: SeismicTransactionSigned =
        tx.into_signed(Signature::new(U256::from(1), U256::from(1), false)).into();
    let recovered = Recovered::new_unchecked(signed, sender);
    let len = recovered.encode_2718_len();
    SeismicPooledTransaction::new(recovered, len)
}

fn storage_outcome(
    address: Address,
    key: U256,
    original: FlaggedStorage,
    present: FlaggedStorage,
) -> ExecutionOutcome<SeismicReceipt> {
    ExecutionOutcome::new_init(
        std::iter::once((
            address,
            (
                Some(Account::default()),
                Some(Account::default()),
                std::iter::once((key.to_be_bytes::<32>().into(), (original, present))).collect(),
            ),
        ))
        .collect(),
        Default::default(),
        [],
        vec![],
        1,
        vec![],
    )
}

fn chain(
    outcome: ExecutionOutcome<SeismicReceipt>,
    timestamp: u64,
) -> Arc<Chain<SeismicPrimitives>> {
    let block = SeismicBlock {
        header: reth_seismic_primitives::SeismicHeader::from(alloy_consensus::Header {
            number: 1,
            gas_limit: 30_000_000,
            timestamp,
            ..Default::default()
        }),
        body: SeismicBlockBody::default(),
    }
    .seal_slow()
    .try_recover()
    .unwrap();
    Arc::new(Chain::new(vec![block], outcome, None))
}

async fn token_only_pool_refresh(case: RefreshCase) {
    let state = TestState { inner: seismic_mock_provider(), ..Default::default() };
    let alice = Address::with_last_byte(1);
    let bob = Address::with_last_byte(2);
    let token = entry(0, 6, 1);
    let precision = TokenPrecision::new(6).unwrap();
    let raw_fee = precision.ceil(U256::from(21_000) * U256::from(10_000_000_000u64));
    seed_registry(&state, &[token]);
    seed_balances(
        &state,
        token,
        &[(alice, FlaggedStorage::public(raw_fee)), (bob, FlaggedStorage::public(raw_fee))],
    );
    for holder in [alice, bob] {
        state.inner.add_account(holder, ExtendedAccount::new(0, U256::ZERO));
    }
    let blobs = InMemoryBlobStore::default();
    let validator = SeismicTransactionValidator::new(
        EthTransactionValidatorBuilder::new(state.inner.clone())
            .no_shanghai()
            .no_cancun()
            .disable_balance_check()
            .build(blobs.clone()),
    );
    let pool = Pool::new(validator, CoinbaseTipOrdering::default(), blobs, Default::default());
    pool.add_transaction(TransactionOrigin::Local, pooled_legacy(alice, 0)).await.unwrap();
    pool.add_transaction(TransactionOrigin::Local, pooled_legacy(bob, 0)).await.unwrap();
    assert_eq!(pool.get_pending_transactions_by_sender(alice).len(), 1);
    assert_eq!(pool.get_pending_transactions_by_sender(bob).len(), 1);

    if matches!(case, RefreshCase::TokenIncrease) {
        pool.add_transaction(TransactionOrigin::Local, pooled_legacy(alice, 1)).await.unwrap();
        assert_eq!(pool.get_queued_transactions_by_sender(alice).len(), 1);
    }
    if matches!(case, RefreshCase::TokenReorg | RefreshCase::RegistryReorg) {
        // The old canonical branch already demoted Alice. The removed branch's
        // storage changes must promote her again using state at the new tip.
        pool.update_accounts(vec![ChangedAccount::empty(alice)]);
        assert_eq!(pool.get_queued_transactions_by_sender(alice).len(), 1);
    }

    let mut new_outcome = ExecutionOutcome::default();
    let mut old_outcome = None;
    match case {
        RefreshCase::TokenDecrease => {
            seed_balances(
                &state,
                token,
                &[(alice, FlaggedStorage::ZERO), (bob, FlaggedStorage::public(raw_fee))],
            );
            new_outcome = storage_outcome(
                token.token,
                balance_storage_key(alice, token.root),
                FlaggedStorage::public(raw_fee),
                FlaggedStorage::ZERO,
            );
        }
        RefreshCase::TokenIncrease => {
            let doubled = raw_fee * U256::from(2);
            seed_balances(
                &state,
                token,
                &[(alice, FlaggedStorage::public(doubled)), (bob, FlaggedStorage::public(raw_fee))],
            );
            new_outcome = storage_outcome(
                token.token,
                balance_storage_key(alice, token.root),
                FlaggedStorage::public(raw_fee),
                FlaggedStorage::public(doubled),
            );
        }
        RefreshCase::TokenReorg => {
            old_outcome = Some(storage_outcome(
                token.token,
                balance_storage_key(alice, token.root),
                FlaggedStorage::public(raw_fee),
                FlaggedStorage::ZERO,
            ));
        }
        RefreshCase::RegistryDeactivate | RefreshCase::RegistryReorg => {
            let slot = token_metadata_slot(0);
            let active_word = state.inner.storage(GAS_TOKEN_REGISTRY, key(slot)).unwrap().unwrap();
            let inactive_word =
                FlaggedStorage::public(active_word.value - (U256::from(1) << 160usize));
            let outcome = storage_outcome(GAS_TOKEN_REGISTRY, slot, active_word, inactive_word);
            if matches!(case, RefreshCase::RegistryDeactivate) {
                seed_registry(&state, &[Entry { active: false, ..token }]);
                new_outcome = outcome;
            } else {
                old_outcome = Some(outcome);
            }
        }
    }
    // No native record identifies either token holder.
    assert!(new_outcome
        .changed_accounts()
        .all(|account| account.address != alice && account.address != bob));
    let new = chain(new_outcome, 0);
    let new_hash = new.tip().hash();
    let event = if let Some(old) = old_outcome {
        reth_provider::CanonStateNotification::Reorg { old: chain(old, 1), new }
    } else {
        reth_provider::CanonStateNotification::Commit { new }
    };
    let discovered = Arc::new(Mutex::new(HashSet::new()));
    let manager = TaskManager::new(tokio::runtime::Handle::current());
    tokio::time::timeout(
        Duration::from_secs(10),
        maintain_transaction_pool_with_hook::<SeismicPrimitives, _, _, _, _, _>(
            state.inner.clone(),
            pool.clone(),
            futures_util::stream::iter([event]),
            manager.executor(),
            Default::default(),
            ObservedHook { discovered: discovered.clone() },
        ),
    )
    .await
    .unwrap();
    assert_eq!(pool.block_info().last_seen_block_hash, new_hash);
    let expected_discovered =
        if matches!(case, RefreshCase::RegistryDeactivate | RefreshCase::RegistryReorg) {
            HashSet::from([alice, bob])
        } else {
            HashSet::from([alice])
        };
    assert_eq!(*discovered.lock().unwrap(), expected_discovered);

    let expected_alice_pending = match case {
        RefreshCase::TokenIncrease => 2,
        RefreshCase::TokenReorg | RefreshCase::RegistryReorg => 1,
        RefreshCase::TokenDecrease | RefreshCase::RegistryDeactivate => 0,
    };
    assert_eq!(pool.get_pending_transactions_by_sender(alice).len(), expected_alice_pending);
    assert_eq!(
        pool.get_queued_transactions_by_sender(alice).len(),
        usize::from(expected_alice_pending == 0)
    );
    assert_eq!(
        pool.get_pending_transactions_by_sender(bob).len(),
        usize::from(!matches!(case, RefreshCase::RegistryDeactivate))
    );
    assert_eq!(pool.unique_senders(), HashSet::from([alice, bob]));
}

#[tokio::test]
async fn token_only_balance_decrease_demotes_without_native_account_changes() {
    token_only_pool_refresh(RefreshCase::TokenDecrease).await;
}

#[tokio::test]
async fn token_only_balance_increase_promotes_a_queued_nonce_sequence() {
    token_only_pool_refresh(RefreshCase::TokenIncrease).await;
}

#[tokio::test]
async fn removed_branch_token_changes_refresh_at_the_new_reorg_tip() {
    token_only_pool_refresh(RefreshCase::TokenReorg).await;
}

#[tokio::test]
async fn registry_deactivation_demotes_all_pooled_holders() {
    token_only_pool_refresh(RefreshCase::RegistryDeactivate).await;
}

#[tokio::test]
async fn removed_branch_registry_changes_refresh_all_holders_at_the_new_tip() {
    token_only_pool_refresh(RefreshCase::RegistryReorg).await;
}

#[test]
fn refresh_error_diagnostics_do_not_expose_private_amounts() {
    let error = SeismicBalanceError::Registry(SeismicPaymentError(
        InvalidTransaction::LackOfFundForMaxFee {
            fee: Box::new(U256::from(987_654_321)),
            balance: Box::new(U256::from(123_456_789)),
        },
    ));
    for text in [
        error.to_string(),
        format!("{error:?}"),
        std::error::Error::source(&error).unwrap().to_string(),
    ] {
        assert!(!text.contains("987654321"));
        assert!(!text.contains("123456789"));
    }
}
