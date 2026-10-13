//! Competing parent-state regressions: prior branch exposure must not affect execution.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use alloy_consensus::Header;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    eth::EthBlockExecutionCtx,
};
use alloy_primitives::{Address, FlaggedStorage, B256, U256};
use alloy_seismic_evm::{CanonicalRotationView, PurposeKeys, RotationEntry, RotationSchedule};
use reth_evm::ConfigureEvm;
use reth_seismic_evm::{PurposeKeyring, SeismicEvmConfig};
use reth_seismic_keys::registry::{rotation_entry_slot, KEY_ROTATION_REGISTRY, ROTATIONS_LEN_SLOT};
use revm::{
    database::{CacheDB, EmptyDB},
    state::{AccountInfo, Bytecode},
    Database,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn config() -> SeismicEvmConfig {
    SeismicEvmConfig::new(
        reth_seismic_chainspec::SEISMIC_MAINNET.clone(),
        Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())),
    )
}

fn branch(activation: Option<u64>) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::default();
    if let Some(activation) = activation {
        db.insert_account_info(KEY_ROTATION_REGISTRY, revm::state::AccountInfo::default());
        db.insert_account_storage(
            KEY_ROTATION_REGISTRY,
            U256::from_be_bytes(ROTATIONS_LEN_SLOT.0),
            U256::from(1).into(),
        )
        .unwrap();
        db.insert_account_storage(
            KEY_ROTATION_REGISTRY,
            U256::from_be_bytes(rotation_entry_slot(0).0),
            U256::from_limbs([1, activation, 101, 0]).into(),
        )
        .unwrap();
    }
    db
}

fn learn_orphan(config: &SeismicEvmConfig) {
    // Model the watcher learning branch A before a reorg. Execution must ignore
    // this metadata even before the watcher has reconciled the replacement head.
    config.executor_factory.keyring.replace_canonical_view(CanonicalRotationView {
        head_hash: B256::repeat_byte(1),
        head_number: 102,
        schedule: RotationSchedule::from_entries([RotationEntry {
            epoch: 1,
            activation_block: 200,
            announced_at_block: 101,
        }])
        .unwrap(),
    });
}

fn pre_execute(
    config: &SeismicEvmConfig,
    activation: Option<u64>,
    number: u64,
) -> Result<Vec<u8>, String> {
    let env = config.evm_env(&Header { number, excess_blob_gas: Some(0), ..Default::default() });
    let mut db = revm::database::State::builder().with_database(branch(activation)).build();
    let evm = config.evm_with_env(&mut db, env);
    let ctx = EthBlockExecutionCtx {
        parent_hash: B256::ZERO,
        parent_beacon_block_root: Some(B256::ZERO),
        ommers: &[],
        withdrawals: None,
    };
    let mut executor = config.executor_factory.create_executor(evm, ctx);
    executor.apply_pre_execution_changes().map_err(|e| e.to_string())?;
    Ok(executor
        .evm()
        .chain
        .process_rng(b"reorg-regression", 32, &B256::ZERO, 100_000)
        .unwrap()
        .to_vec())
}

#[test]
fn orphan_without_keys_does_not_break_replacement_branch() {
    let exposed = config();
    learn_orphan(&exposed);
    assert_eq!(
        pre_execute(&exposed, None, 200).unwrap(),
        pre_execute(&config(), None, 200).unwrap()
    );
}

#[test]
fn fetched_orphan_does_not_change_rng_for_identical_parent() {
    let exposed = config();
    learn_orphan(&exposed);
    let mut keys = PurposeKeys::well_known();
    keys.rng_ikm = [42; 64];
    exposed.executor_factory.keyring.insert_epoch(1, keys).unwrap();
    assert_eq!(
        pre_execute(&exposed, None, 200).unwrap(),
        pre_execute(&config(), None, 200).unwrap()
    );
}

#[test]
fn replacement_activation_is_selected_from_parent() {
    let exposed = config();
    let clean = config();
    learn_orphan(&exposed);
    let mut keys = PurposeKeys::well_known();
    keys.rng_ikm = [42; 64];
    for node in [&exposed, &clean] {
        node.executor_factory.keyring.insert_epoch(1, keys.clone()).unwrap();
    }
    for number in [200, 299, 300, 301] {
        assert_eq!(
            pre_execute(&exposed, Some(300), number).unwrap(),
            pre_execute(&clean, Some(300), number).unwrap(),
            "block {number}"
        );
    }
}

#[test]
fn missing_parent_epoch_is_retryable_without_schedule_publication() {
    let node = config();
    let error = pre_execute(&node, Some(200), 200).unwrap_err();
    assert!(error.contains("purpose keys for epoch 1"), "{error}");
    assert_eq!(node.executor_factory.keyring.requested_epochs(), vec![1]);
    assert_eq!(node.executor_factory.keyring.schedule_len(), 0);
    // The failed attempt never changes selection to an available epoch.
    assert!(pre_execute(&node, Some(200), 200).is_err());
    assert_eq!(node.executor_factory.keyring.requested_epochs(), vec![1]);
    let mut keys = PurposeKeys::well_known();
    keys.rng_ikm = [42; 64];
    node.executor_factory.keyring.insert_epoch(1, keys).unwrap();
    assert!(node.executor_factory.keyring.requested_epochs().is_empty());
    assert_ne!(pre_execute(&node, Some(200), 200).unwrap(), pre_execute(&node, None, 200).unwrap());
}

#[derive(Debug)]
struct ObservedDb {
    inner: CacheDB<EmptyDB>,
    reads: Arc<AtomicUsize>,
    fail_basic: bool,
    fail_storage: bool,
}

#[derive(Debug)]
struct RegistryUnavailable(&'static str);

impl std::fmt::Display for RegistryUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for RegistryUnavailable {}
impl revm::database_interface::DBErrorMarker for RegistryUnavailable {}

impl Database for ObservedDb {
    type Error = RegistryUnavailable;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if self.fail_basic {
            return Err(RegistryUnavailable("registry basic unavailable"));
        }
        Ok(self.inner.basic(address).unwrap())
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<FlaggedStorage, Self::Error> {
        if address == KEY_ROTATION_REGISTRY {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_storage {
                return Err(RegistryUnavailable("registry storage unavailable"));
            }
        }
        Ok(self.inner.storage(address, slot).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.inner.code_by_hash(hash).unwrap())
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.inner.block_hash(number).unwrap())
    }
}

#[test]
fn registry_read_failures_never_use_cached_or_fallback_keys() {
    for fail_basic in [true, false] {
        let node = config();
        let db = ObservedDb {
            inner: branch(Some(300)),
            reads: Arc::default(),
            fail_basic,
            fail_storage: !fail_basic,
        };
        let env = node.evm_env(&Header { number: 200, ..Default::default() });
        let mut state = revm::database::State::builder().with_database(db).build();
        let evm = node.evm_with_env(&mut state, env);
        let ctx = EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
        };
        let mut executor = node.executor_factory.create_executor(evm, ctx);
        let error = executor.apply_pre_execution_changes().unwrap_err();
        assert!(error.to_string().contains("registry"), "{error}");
        assert!(!error.is_retryable(), "storage errors are not missing-key requests");
        assert!(node.executor_factory.keyring.requested_epochs().is_empty());
    }
}

#[test]
fn raw_and_inspected_simulations_use_parent_state_once_without_fetch_requests() {
    let live = config();
    learn_orphan(&live);
    let simulation = live.snapshot_for_simulation();
    let reads = Arc::new(AtomicUsize::new(0));
    let db = ObservedDb {
        inner: branch(Some(300)),
        reads: reads.clone(),
        fail_basic: false,
        fail_storage: false,
    };
    let env = simulation.evm_env(&Header { number: 200, ..Default::default() });
    let mut evm = simulation.evm_with_env_and_inspector(db, env, revm::inspector::NoOpInspector {});
    assert_eq!(evm.initialize_keys().unwrap().epoch, 0);
    assert_eq!(evm.initialize_keys().unwrap().epoch, 0);
    assert_eq!(reads.load(Ordering::SeqCst), 2, "length plus one entry, once per attempt");
    let env = simulation.evm_env(&Header { number: 300, ..Default::default() });
    let mut evm = simulation.evm_with_env(branch(Some(300)), env);
    assert!(evm.initialize_keys().unwrap_err().to_string().contains("epoch 1"));
    assert!(live.executor_factory.keyring.requested_epochs().is_empty());
}

#[test]
fn side_branch_execution_does_not_publish_announcements() {
    let node = config();
    pre_execute(&node, Some(300), 102).unwrap();
    assert_eq!(node.executor_factory.keyring.pending(), None);
    assert_eq!(node.executor_factory.keyring.schedule_len(), 0);
}
