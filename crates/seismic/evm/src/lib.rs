//! EVM config for vanilla seismic.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{borrow::Cow, sync::Arc};
use alloy_consensus::{BlockHeader, Header};
use alloy_eips::{eip1559::INITIAL_BASE_FEE, Decodable2718};
use alloy_evm::{eth::EthBlockExecutionCtx, EvmFactory};
use alloy_primitives::{Bytes, U256};
pub use alloy_seismic_evm::{
    block::SeismicBlockExecutorFactory, PurposeKeyring, SeismicBlockEnv, SeismicEvm, SeismicEvmEnv,
    SeismicEvmFactory,
};
use build::SeismicBlockAssembler;
use core::fmt::Debug;
use reth_chainspec::EthChainSpec;
use reth_ethereum_forks::EthereumHardfork;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    NextBlockEnvAttributes,
};
use reth_primitives_traits::{SealedBlock, SealedHeader, SignedTransaction, TxTy};
use reth_seismic_chainspec::SeismicChainSpec;
use reth_seismic_engine_primitives::SeismicExecutionData;
use reth_seismic_primitives::{SeismicBlock, SeismicHeader, SeismicPrimitives};
use reth_storage_errors::any::AnyError;
use revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
};
use seismic_revm::SeismicSpecId;
use std::convert::Infallible;

mod receipts;
pub use receipts::*;
mod build;

mod context;
pub use context::{
    SeismicBlockExecutionCtx, SeismicNextBlockEnvAttributes, SeismicRethBlockExecutorFactory,
};

pub mod config;
use config::revm_spec;

/// Seismic EVM configuration.
#[derive(Debug, Clone)]
pub struct SeismicEvmConfig {
    /// Block executor factory (wraps the fork's [`SeismicBlockExecutorFactory`]).
    pub executor_factory: SeismicRethBlockExecutorFactory,
    /// Seismic block assembler.
    pub block_assembler: SeismicBlockAssembler<SeismicChainSpec>,
}

impl SeismicEvmConfig {
    /// Creates a new Seismic EVM configuration with the given chain spec and the
    /// epoch-keyed purpose keyring.
    pub fn new(chain_spec: Arc<SeismicChainSpec>, keyring: Arc<PurposeKeyring>) -> Self {
        Self::new_with_evm_factory(chain_spec, SeismicEvmFactory::new(keyring.clone()), keyring)
    }

    /// Creates a new Ethereum EVM configuration with the given chain spec and EVM factory.
    pub fn new_with_evm_factory(
        chain_spec: Arc<SeismicChainSpec>,
        evm_factory: SeismicEvmFactory,
        keyring: Arc<PurposeKeyring>,
    ) -> Self {
        Self {
            block_assembler: SeismicBlockAssembler::new(chain_spec.clone()),
            executor_factory: SeismicRethBlockExecutorFactory::new(
                SeismicBlockExecutorFactory::new(
                    SeismicRethReceiptBuilder::default(),
                    chain_spec,
                    evm_factory,
                    keyring,
                ),
            ),
        }
    }

    /// Creates a request-local configuration with an independent purpose keyring.
    ///
    /// Both factories share a request-local handle to additive key material, with
    /// fetch requests disabled and no inherited canonical metadata. Schedules are
    /// resolved from each simulated parent's database overlay. Its block executor
    /// accepts authenticated plaintext signed reads prepared by RPC ingress, without
    /// decrypting them again; ordinary encrypted replay remains unchanged.
    pub fn snapshot_for_simulation(&self) -> Self {
        let inner = &self.executor_factory.inner;
        let keyring = Arc::new(inner.keyring.snapshot());
        Self {
            executor_factory: SeismicRethBlockExecutorFactory::new(
                SeismicBlockExecutorFactory::new(
                    *inner.receipt_builder(),
                    inner.spec().clone(),
                    SeismicEvmFactory::new(keyring.clone()),
                    keyring,
                )
                .with_plaintext_signed_reads(),
            ),
            block_assembler: self.block_assembler.clone(),
        }
    }

    /// Returns the chain spec associated with this configuration.
    pub const fn chain_spec(&self) -> &Arc<SeismicChainSpec> {
        self.executor_factory.inner.spec()
    }

    /// Sets the extra data for the block assembler.
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.block_assembler.extra_data = extra_data;
        self
    }

    /// Creates an EVM that resolves keys from its own execution state before its
    /// first operation. Construction never reads or publishes a global schedule.
    pub fn evm_with_env_and_live_key<DB>(
        &self,
        db: DB,
        evm_env: SeismicEvmEnv,
    ) -> SeismicEvm<DB, revm::inspector::NoOpInspector>
    where
        DB: alloy_evm::Database,
    {
        self.executor_factory.inner.evm_factory().create_evm(db, evm_env)
    }

    fn cfg_env(&self, spec: SeismicSpecId) -> CfgEnv<SeismicSpecId> {
        // `enable_tx_chain_id_check` enforces EIP-155 chain-domain separation during
        // execution, so a transaction signed for a different chain cannot execute even
        // if it reaches block import (e.g. via `engine_newPayload`) without passing
        // through the local txpool, which performs the same check on admission.
        CfgEnv::new()
            .with_chain_id(self.chain_spec().chain().id())
            .with_spec(spec)
            .enable_tx_chain_id_check()
    }
}

impl ConfigureEvm for SeismicEvmConfig {
    type Primitives = SeismicPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = SeismicNextBlockEnvAttributes;
    type BlockExecutorFactory = SeismicRethBlockExecutorFactory;
    type BlockAssembler = SeismicBlockAssembler<SeismicChainSpec>;

    fn snapshot_for_simulation(
        &self,
    ) -> impl ConfigureEvm<
        Primitives = Self::Primitives,
        Error = Self::Error,
        NextBlockEnvCtx = Self::NextBlockEnvCtx,
        BlockExecutorFactory = Self::BlockExecutorFactory,
        BlockAssembler = Self::BlockAssembler,
    > {
        Self::snapshot_for_simulation(self)
    }

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &SeismicHeader) -> SeismicEvmEnv {
        let spec = revm_spec(self.chain_spec(), header);
        let cfg_env = self.cfg_env(spec);

        let block_env = BlockEnv {
            number: U256::from(header.number()),
            beneficiary: header.beneficiary(),
            timestamp: U256::from(header.timestamp()),
            difficulty: U256::ZERO,
            prevrandao: header.mix_hash(), /* Seismic genesis spec (Mercury) starts after Paris,
                                            * so we always use header.mix_hash() */
            gas_limit: header.gas_limit(),
            basefee: header.base_fee_per_gas().unwrap_or_default(),
            // EIP-4844 excess blob gas of this block, introduced in Cancun
            blob_excess_gas_and_price: header.excess_blob_gas().map(|excess_blob_gas| {
                BlobExcessGasAndPrice::new_with_spec(excess_blob_gas, spec.into_eth_spec())
            }),
        };

        let block_env = SeismicBlockEnv {
            inner: block_env,
            timestamp_millis_part: header.timestamp_millis_part,
        };
        EvmEnv { cfg_env, block_env }
    }

    fn next_evm_env(
        &self,
        parent: &SeismicHeader,
        attributes: &SeismicNextBlockEnvAttributes,
    ) -> Result<SeismicEvmEnv, Self::Error> {
        let timestamp_millis_part = attributes.timestamp_millis_part;
        let spec_id = revm_spec(self.chain_spec(), parent);
        let cfg = self.cfg_env(spec_id);
        let attributes: &NextBlockEnvAttributes = attributes;

        // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // cancun now, we need to set the excess blob gas to the default value(0)
        let blob_excess_gas_and_price = parent
            .inner
            .maybe_next_block_excess_blob_gas(
                self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
            )
            .map(|gas| BlobExcessGasAndPrice::new_with_spec(gas, spec_id.into_eth_spec()));

        let mut basefee = parent.inner.next_block_base_fee(
            self.chain_spec().base_fee_params_at_timestamp(attributes.timestamp),
        );

        let mut gas_limit = attributes.gas_limit;

        // If we are on the London fork boundary, we need to multiply the parent's gas limit by the
        // elasticity multiplier to get the new gas limit.
        if self
            .chain_spec()
            .fork(EthereumHardfork::London)
            .transitions_at_block(parent.number() + 1)
        {
            let elasticity_multiplier = self
                .chain_spec()
                .base_fee_params_at_timestamp(attributes.timestamp)
                .elasticity_multiplier;

            // multiply the gas limit by the elasticity multiplier
            gas_limit *= elasticity_multiplier as u64;

            // set the base fee to the initial base fee from the EIP-1559 spec
            basefee = Some(INITIAL_BASE_FEE)
        }

        let block_env = BlockEnv {
            number: U256::from(parent.number() + 1),
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: U256::from(attributes.timestamp),
            difficulty: U256::ZERO,
            prevrandao: Some(attributes.prev_randao),
            gas_limit,
            // calculate basefee based on parent block's gas usage
            basefee: basefee.unwrap_or_default(),
            // calculate excess gas based on parent block's blob gas usage
            blob_excess_gas_and_price,
        };

        let block_env = SeismicBlockEnv { inner: block_env, timestamp_millis_part };
        Ok((cfg, block_env).into())
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<SeismicBlock>,
    ) -> SeismicBlockExecutionCtx<'a> {
        SeismicBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: block.header().parent_hash(),
                parent_beacon_block_root: block.header().parent_beacon_block_root(),
                // Post-merge blocks carry no ommers.
                ommers: &[],
                withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
            },
            timestamp_millis_part: block.header().timestamp_millis_part,
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<SeismicHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> SeismicBlockExecutionCtx<'_> {
        SeismicBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: attributes.inner.parent_beacon_block_root,
                ommers: &[],
                withdrawals: attributes.inner.withdrawals.map(Cow::Owned),
            },
            timestamp_millis_part: attributes.timestamp_millis_part,
        }
    }

    /// Override to use pre-fetched live RNG key
    fn evm_with_env<DB: alloy_evm::Database>(
        &self,
        db: DB,
        evm_env: SeismicEvmEnv,
    ) -> SeismicEvm<DB, revm::inspector::NoOpInspector> {
        self.evm_with_env_and_live_key(db, evm_env)
    }
}

impl ConfigureEngineEvm<SeismicExecutionData> for SeismicEvmConfig {
    fn evm_env_for_payload(&self, payload: &SeismicExecutionData) -> EvmEnvFor<Self> {
        let payload = &payload.payload;
        // Create a temporary header with the payload information to determine the spec
        let temp_header = SeismicHeader::new(
            Header {
                number: payload.block_number(),
                timestamp: payload.timestamp(),
                gas_limit: payload.inner.payload_inner.payload_inner.gas_limit,
                beneficiary: payload.inner.payload_inner.payload_inner.fee_recipient,
                ..Default::default()
            },
            payload.timestamp_millis_part,
        );
        let spec_id = revm_spec(self.chain_spec(), &temp_header);
        let cfg_env = self.cfg_env(spec_id);

        let blob_excess_gas_and_price =
            Some(BlobExcessGasAndPrice::new_with_spec(0, spec_id.into_eth_spec()));

        let inner = &payload.inner.payload_inner.payload_inner;
        let block_env = BlockEnv {
            number: U256::from(inner.block_number),
            beneficiary: inner.fee_recipient,
            timestamp: U256::from(inner.timestamp),
            difficulty: U256::ZERO,
            prevrandao: Some(inner.prev_randao),
            gas_limit: inner.gas_limit,
            basefee: inner.base_fee_per_gas.saturating_to(),
            blob_excess_gas_and_price,
        };

        let block_env = SeismicBlockEnv {
            inner: block_env,
            timestamp_millis_part: payload.timestamp_millis_part,
        };
        (cfg_env, block_env).into()
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a SeismicExecutionData,
    ) -> ExecutionCtxFor<'a, Self> {
        SeismicBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: payload.payload.parent_hash(),
                parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
                ommers: &[],
                withdrawals: Some(Cow::Owned(
                    payload.payload.inner.payload_inner.withdrawals.clone().into(),
                )),
            },
            timestamp_millis_part: payload.payload.timestamp_millis_part,
        }
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &SeismicExecutionData,
    ) -> impl ExecutableTxIterator<Self> {
        payload.payload.inner.payload_inner.payload_inner.transactions.clone().into_iter().map(
            |tx| {
                let mut tx_data = tx.as_ref();
                let tx =
                    TxTy::<Self::Primitives>::decode_2718(&mut tx_data).map_err(AnyError::new)?;
                let signer = tx.try_recover().map_err(AnyError::new)?;
                Ok::<_, AnyError>(tx.with_signer(signer))
            },
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test code - expect on failure is acceptable
#[allow(clippy::unwrap_used)] // Test code - unwrap on failure is acceptable
#[allow(clippy::panic)] // Test code - panic on failure is acceptable
mod tests {
    use super::*;
    use alloy_consensus::{Header, Receipt};
    use alloy_eips::eip7685::Requests;
    use alloy_evm::Evm;
    use alloy_genesis::Genesis;
    use alloy_primitives::{bytes, map::HashMap, Address, LogData, TxKind, B256, U256};
    use alloy_seismic_evm::PurposeKeys;
    use reth_chainspec::ChainSpec;
    use reth_evm::execute::ProviderError;
    use reth_execution_types::{
        AccountRevertInit, BundleStateInit, Chain, ExecutionOutcome, RevertsInit,
    };
    use reth_primitives_traits::{Account, RecoveredBlock};
    use reth_seismic_chainspec::{SeismicChainSpec, SEISMIC_MAINNET};
    use reth_seismic_primitives::{SeismicBlock, SeismicHeader, SeismicPrimitives, SeismicReceipt};
    use revm::{
        context::{
            result::{EVMError, InvalidTransaction},
            TxEnv,
        },
        database::{BundleState, CacheDB},
        database_interface::EmptyDBTyped,
        handler::PrecompileProvider,
        inspector::NoOpInspector,
        precompile::u64_to_address,
        primitives::Log,
        state::AccountInfo,
    };
    use seismic_revm::transaction::abstraction::SeismicTransaction;
    use std::sync::Arc;

    fn test_evm_config() -> SeismicEvmConfig {
        SeismicEvmConfig::new(
            SEISMIC_MAINNET.clone(),
            Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())),
        )
    }

    #[test]
    fn simulation_snapshot_preserves_config_and_isolates_both_factories() {
        use alloy_evm::block::{BlockExecutor, BlockExecutorFactory};
        use alloy_seismic_evm::{CanonicalRotationView, RotationEntry, RotationSchedule};

        let live = test_evm_config().with_extra_data(bytes!("1234"));
        let snapshot = live.snapshot_for_simulation();
        assert_eq!(snapshot.block_assembler.extra_data, live.block_assembler.extra_data);
        assert!(Arc::ptr_eq(snapshot.chain_spec(), live.chain_spec()));
        assert!(!Arc::ptr_eq(&snapshot.executor_factory.keyring, &live.executor_factory.keyring));

        let keyring = &snapshot.executor_factory.keyring;
        keyring.replace_canonical_view(CanonicalRotationView {
            head_hash: B256::repeat_byte(1),
            head_number: 100,
            schedule: RotationSchedule::from_entries([RotationEntry {
                epoch: 1,
                activation_block: 100,
                announced_at_block: 10,
            }])
            .unwrap(),
        });
        let mut keys = PurposeKeys::well_known();
        keys.rng_ikm = [42; 64];
        live.executor_factory.keyring.insert_epoch(1, keys).unwrap();
        let env = snapshot.evm_env(&SeismicHeader::from(Header {
            number: 100,
            excess_blob_gas: Some(0),
            ..Default::default()
        }));

        let mut db = revm::database::State::builder()
            .with_database(EmptyDBTyped::<ProviderError>::default())
            .build();
        let mut evm = snapshot.evm_with_env(&mut db, env.clone());
        evm.initialize_keys().unwrap();
        let rng_before = evm.chain.process_rng(b"snapshot", 32, &B256::ZERO, 100_000).unwrap();
        let mut live_evm = live.evm_with_env(EmptyDBTyped::<ProviderError>::default(), env.clone());
        live_evm.initialize_keys().unwrap();
        let live_rng = live_evm.chain.process_rng(b"snapshot", 32, &B256::ZERO, 100_000).unwrap();
        assert_eq!(rng_before, live_rng, "canonical metadata must not override empty parent state");
        let mut inspected = snapshot.evm_with_env_and_inspector(
            EmptyDBTyped::<ProviderError>::default(),
            env,
            NoOpInspector {},
        );
        inspected.initialize_keys().unwrap();
        assert_eq!(
            rng_before,
            inspected.chain.process_rng(b"snapshot", 32, &B256::ZERO, 100_000).unwrap(),
            "inspected EVMs must use the snapshot's RNG key too",
        );

        let ctx = SeismicBlockExecutionCtx {
            timestamp_millis_part: 0,
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: Some(B256::ZERO),
                ommers: &[],
                withdrawals: None,
            },
        };
        let mut executor = snapshot.executor_factory.create_executor(evm, ctx);
        executor.apply_pre_execution_changes().unwrap();
        let rng_after =
            executor.evm().chain.process_rng(b"snapshot", 32, &B256::ZERO, 100_000).unwrap();
        assert_eq!(rng_before, rng_after, "block executor must use the same snapshot key");
        assert_eq!(live.executor_factory.keyring.schedule_len(), 0);
        // Fetched epoch material is additive and shared, but is not selection authority.
        assert!(live.executor_factory.keyring.keys_for_epoch(1).is_some());
    }

    #[test]
    fn simulation_snapshot_refresh_keeps_speculative_schedule_local() {
        use alloy_evm::block::{BlockExecutor, BlockExecutorFactory};
        use reth_seismic_keys::registry::{
            rotation_entry_slot, KEY_ROTATION_REGISTRY, ROTATIONS_LEN_SLOT,
        };

        let live = test_evm_config();
        live.executor_factory.keyring.replace_canonical_view(
            alloy_seismic_evm::CanonicalRotationView {
                head_hash: B256::repeat_byte(1),
                head_number: 100,
                ..Default::default()
            },
        );
        let snapshot = live.snapshot_for_simulation();
        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let env =
            snapshot.evm_env(&SeismicHeader::from(Header { number: 101, ..Default::default() }));
        drop(snapshot.evm_with_env(&mut db, env));

        // Model an announcement committed to the request's overlay in its first
        // simulated block. This is fixture setup, not a permitted RPC override.
        db.insert_account_info(KEY_ROTATION_REGISTRY, AccountInfo::default());
        db.insert_account_storage(
            KEY_ROTATION_REGISTRY,
            U256::from_be_bytes(ROTATIONS_LEN_SLOT.0),
            U256::from(1).into(),
        )
        .unwrap();
        db.insert_account_storage(
            KEY_ROTATION_REGISTRY,
            U256::from_be_bytes(rotation_entry_slot(0).0),
            U256::from_limbs([1, 200, 101, 0]).into(),
        )
        .unwrap();
        let env =
            snapshot.evm_env(&SeismicHeader::from(Header { number: 102, ..Default::default() }));
        drop(snapshot.evm_with_env(&mut db, env));
        assert_eq!(snapshot.executor_factory.keyring.pending(), None);
        assert!(snapshot.executor_factory.keyring.unfetched_scheduled_epochs().is_empty());
        assert_eq!(live.executor_factory.keyring.schedule_len(), 0);
        assert_eq!(live.executor_factory.keyring.known_tip(), 100);
        assert!(live.executor_factory.keyring.unfetched_scheduled_epochs().is_empty());
        assert_eq!(live.snapshot_for_simulation().executor_factory.keyring.schedule_len(), 0);

        // Crossing an unfetched epoch fails locally; even that error must not
        // publish a fetch request to the live watcher's keyring.
        let mut db = revm::database::State::builder().with_database(db).build();
        let env =
            snapshot.evm_env(&SeismicHeader::from(Header { number: 200, ..Default::default() }));
        let evm = snapshot.evm_with_env(&mut db, env);
        let ctx = SeismicBlockExecutionCtx {
            timestamp_millis_part: 0,
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: None,
                ommers: &[],
                withdrawals: None,
            },
        };
        let mut executor = snapshot.executor_factory.create_executor(evm, ctx);
        let error = executor.apply_pre_execution_changes().unwrap_err();
        assert!(error.is_retryable());
        assert!(live.executor_factory.keyring.requested_epochs().is_empty());
        assert_eq!(live.executor_factory.keyring.schedule_len(), 0);
        assert!(live.executor_factory.keyring.unfetched_scheduled_epochs().is_empty());
    }

    #[test]
    fn simulation_snapshot_hook_forwards_through_reference_and_arc() {
        let live = test_evm_config();
        let by_ref = &live;
        let by_arc = Arc::new(live.clone());
        let from_ref = ConfigureEvm::snapshot_for_simulation(&by_ref);
        let from_arc = ConfigureEvm::snapshot_for_simulation(&by_arc);
        assert!(!Arc::ptr_eq(
            &from_ref.block_executor_factory().keyring,
            &live.executor_factory.keyring
        ));
        assert!(!Arc::ptr_eq(
            &from_arc.block_executor_factory().keyring,
            &live.executor_factory.keyring
        ));
    }

    #[test]
    fn test_fill_cfg_and_block_env() {
        // Create a default header
        let header = Header::default();

        // Build the ChainSpec for Ethereum mainnet, activating London, Paris, and Shanghai
        // hardforks
        let chain_spec = ChainSpec::builder()
            .chain(0.into())
            .genesis(Genesis::default())
            .london_activated()
            .paris_activated()
            .shanghai_activated()
            .build();

        // Use the `SeismicEvmConfig` to create the `cfg_env` and `block_env` based on the
        // ChainSpec, Header, and total difficulty
        let keyring = Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known()));
        let EvmEnv { cfg_env, .. } =
            SeismicEvmConfig::new(Arc::new(SeismicChainSpec::from(chain_spec.clone())), keyring)
                .evm_env(&SeismicHeader::from(header));

        // Assert that the chain ID in the `cfg_env` is correctly set to the chain ID of the
        // ChainSpec
        assert_eq!(cfg_env.chain_id, chain_spec.chain().id());
    }

    #[test]
    fn test_seismic_evm_with_env_default_spec() {
        // Setup the EVM with test config and environment
        let evm_config = test_evm_config(); // Provides SeismicEvm config with Seismic mainnet spec
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let evm_env = EvmEnv::default();
        let evm: SeismicEvm<_, NoOpInspector> = evm_config.evm_with_env(db, evm_env.clone());
        let precompiles = evm.precompiles().clone();

        // Check that the EVM environment is correctly set
        assert_eq!(evm.cfg, evm_env.cfg_env);
        assert_eq!(evm.cfg.spec, SeismicSpecId::MERCURY);

        // Check that the expected number of precompiles is set
        let precompile_addresses =
            [u64_to_address(101), u64_to_address(102), u64_to_address(103), u64_to_address(104)];
        for &addr in &precompile_addresses {
            let is_contained = precompiles.contains(&addr);
            assert!(
                is_contained,
                "Expected Precompile at address for RETH evm generation {addr:?}"
            );
        }
    }

    #[test]
    fn test_evm_with_env_custom_cfg() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create a custom configuration environment with a chain ID of 111
        let cfg = CfgEnv::new().with_chain_id(111).with_spec(SeismicSpecId::default());

        let evm_env = EvmEnv { cfg_env: cfg.clone(), ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env);

        // Check that the EVM environment is initialized with the custom environment
        assert_eq!(evm.cfg, cfg);
    }

    #[test]
    fn test_evm_with_env_custom_block_and_tx() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create customs block and tx env
        let block = BlockEnv {
            basefee: 1000,
            gas_limit: 10_000_000,
            number: U256::from(42),
            ..Default::default()
        };

        let evm_env = SeismicEvmEnv { block_env: block.into(), ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        // Verify that the block and transaction environments are set correctly
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn test_evm_with_spec_id() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new().with_spec(SeismicSpecId::MERCURY),
            ..Default::default()
        };

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_and_default_inspector() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv { cfg_env: Default::default(), ..Default::default() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the EVM environment is set to default values
        assert_eq!(*evm.block(), evm_env.block_env.inner);
        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_custom_cfg() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let cfg = CfgEnv::new().with_chain_id(111).with_spec(SeismicSpecId::MERCURY);
        let block = BlockEnv::default();
        let evm_env = SeismicEvmEnv { block_env: block.into(), cfg_env: cfg.clone() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the EVM environment is set with custom configuration
        assert_eq!(evm.cfg, cfg);
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_custom_block_tx() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create custom block and tx environment
        let block = BlockEnv {
            basefee: 1000,
            gas_limit: 10_000_000,
            number: U256::from(42),
            ..Default::default()
        };
        let evm_env = SeismicEvmEnv { block_env: block.into(), ..Default::default() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Verify that the block and transaction environments are set correctly
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_spec_id() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new().with_spec(SeismicSpecId::MERCURY),
            ..Default::default()
        };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the spec ID is set properly
        assert_eq!(evm.cfg, evm_env.cfg_env);
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn receipts_by_block_hash() {
        // Create a default recovered block
        let block: RecoveredBlock<SeismicBlock> = Default::default();

        // Define block hashes for block1 and block2
        let block1_hash = B256::new([0x01; 32]);
        let block2_hash = B256::new([0x02; 32]);

        // Clone the default block into block1 and block2
        let mut block1 = block.clone();
        let mut block2 = block;

        // Set the hashes of block1 and block2
        block1.set_block_number(10);
        block1.set_hash(block1_hash);

        block2.set_block_number(11);
        block2.set_hash(block2_hash);

        // Create a random receipt object, receipt1
        let receipt1 = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create another random receipt object, receipt2
        let receipt2 = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 1325345,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![receipt1.clone()], vec![receipt2]];

        // Create an ExecutionOutcome object with the created bundle, receipts, an empty requests
        // vector, and first_block set to 10
        let execution_outcome = ExecutionOutcome::<SeismicReceipt> {
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block: 10,
        };

        // Create a Chain object with a BTreeMap of blocks mapped to their block numbers,
        // including block1_hash and block2_hash, and the execution_outcome
        let chain: Chain<SeismicPrimitives> =
            Chain::new([block1, block2], execution_outcome.clone(), None);

        // Assert that the proper receipt vector is returned for block1_hash
        assert_eq!(chain.receipts_by_block_hash(block1_hash), Some(vec![&receipt1]));

        // Create an ExecutionOutcome object with a single receipt vector containing receipt1
        let execution_outcome1 = ExecutionOutcome {
            bundle: Default::default(),
            receipts: vec![vec![receipt1]],
            requests: vec![],
            first_block: 10,
        };

        // Assert that the execution outcome at the first block contains only the first receipt
        assert_eq!(chain.execution_outcome_at_block(10), Some(execution_outcome1));

        // Assert that the execution outcome at the tip block contains the whole execution outcome
        assert_eq!(chain.execution_outcome_at_block(11), Some(execution_outcome));
    }

    #[test]
    fn test_initialisation() {
        // Create a new BundleState object with initial data
        let bundle = BundleState::new(
            vec![(Address::new([2; 20]), None, Some(AccountInfo::default()), HashMap::default())],
            vec![vec![(Address::new([2; 20]), None, vec![])]],
            vec![],
        );

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        }))]];

        // Create a Requests object with a vector of requests
        let requests = vec![Requests::new(vec![bytes!("dead"), bytes!("beef"), bytes!("beebee")])];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: bundle.clone(),
            receipts: receipts.clone(),
            requests: requests.clone(),
            first_block,
        };

        // Assert that creating a new ExecutionOutcome using the constructor matches exec_res
        assert_eq!(
            ExecutionOutcome::new(bundle, receipts.clone(), first_block, requests.clone()),
            exec_res
        );

        // Create a BundleStateInit object and insert initial data
        let mut state_init: BundleStateInit = HashMap::default();
        state_init
            .insert(Address::new([2; 20]), (None, Some(Account::default()), HashMap::default()));

        // Create a HashMap for account reverts and insert initial data
        let mut revert_inner: HashMap<Address, AccountRevertInit> = HashMap::default();
        revert_inner.insert(Address::new([2; 20]), (None, vec![]));

        // Create a RevertsInit object and insert the revert_inner data
        let mut revert_init: RevertsInit = HashMap::default();
        revert_init.insert(123, revert_inner);

        // Assert that creating a new ExecutionOutcome using the new_init method matches
        // exec_res
        assert_eq!(
            ExecutionOutcome::new_init(
                state_init,
                revert_init,
                vec![],
                receipts,
                first_block,
                requests,
            ),
            exec_res
        );
    }

    #[test]
    fn test_block_number_to_index() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        }))]];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block,
        };

        // Test before the first block
        assert_eq!(exec_res.block_number_to_index(12), None);

        // Test after after the first block but index larger than receipts length
        assert_eq!(exec_res.block_number_to_index(133), None);

        // Test after the first block
        assert_eq!(exec_res.block_number_to_index(123), Some(0));
    }

    #[test]
    fn test_get_logs() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![Log::<LogData>::default()],
            status: true.into(),
        })]];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block,
        };

        // Get logs for block number 123
        let logs: Vec<&Log> = exec_res.logs(123).unwrap().collect();

        // Assert that the logs match the expected logs
        assert_eq!(logs, vec![&Log::<LogData>::default()]);
    }

    #[test]
    fn test_receipts_by_block() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![Log::<LogData>::default()],
            status: true.into(),
        }))]];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(), // Default value for bundle
            receipts,                   // Include the created receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Get receipts for block number 123 and convert the result into a vector
        let receipts_by_block: Vec<_> = exec_res.receipts_by_block(123).iter().collect();

        // Assert that the receipts for block number 123 match the expected receipts
        assert_eq!(
            receipts_by_block,
            vec![&Some(SeismicReceipt::Legacy(Receipt {
                cumulative_gas_used: 46913,
                logs: vec![Log::<LogData>::default()],
                status: true.into(),
            }))]
        );
    }

    #[test]
    fn test_receipts_len() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![Log::<LogData>::default()],
            status: true.into(),
        }))]];

        // Create an empty Receipts object
        let receipts_empty = vec![];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(), // Default value for bundle
            receipts,                   // Include the created receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Assert that the length of receipts in exec_res is 1
        assert_eq!(exec_res.len(), 1);

        // Assert that exec_res is not empty
        assert!(!exec_res.is_empty());

        // Create a ExecutionOutcome object with an empty Receipts object
        let exec_res_empty_receipts: ExecutionOutcome<SeismicReceipt> = ExecutionOutcome {
            bundle: Default::default(), // Default value for bundle
            receipts: receipts_empty,   // Include the empty receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Assert that the length of receipts in exec_res_empty_receipts is 0
        assert_eq!(exec_res_empty_receipts.len(), 0);

        // Assert that exec_res_empty_receipts is empty
        assert!(exec_res_empty_receipts.is_empty());
    }

    #[test]
    fn test_revert_to() {
        // Create a random receipt object
        let receipt = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(receipt.clone())], vec![Some(receipt.clone())]];

        // Define the first block number
        let first_block = 123;

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests =
            vec![Requests::new(vec![request.clone()]), Requests::new(vec![request.clone()])];

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let mut exec_res =
            ExecutionOutcome { bundle: Default::default(), receipts, requests, first_block };

        // Assert that the revert_to method returns true when reverting to the initial block number.
        assert!(exec_res.revert_to(123));

        // Assert that the receipts are properly cut after reverting to the initial block number.
        assert_eq!(exec_res.receipts, vec![vec![Some(receipt)]]);

        // Assert that the requests are properly cut after reverting to the initial block number.
        assert_eq!(exec_res.requests, vec![Requests::new(vec![request])]);

        // Assert that the revert_to method returns false when attempting to revert to a block
        // number greater than the initial block number.
        assert!(!exec_res.revert_to(133));

        // Assert that the revert_to method returns false when attempting to revert to a block
        // number less than the initial block number.
        assert!(!exec_res.revert_to(10));
    }

    #[test]
    fn test_extend_execution_outcome() {
        // Create a Receipt object with specific attributes.
        let receipt = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object containing the receipt.
        let receipts = vec![vec![Some(receipt.clone())]];

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests = vec![Requests::new(vec![request.clone()])];

        // Define the initial block number.
        let first_block = 123;

        // Create an ExecutionOutcome object.
        let mut exec_res =
            ExecutionOutcome { bundle: Default::default(), receipts, requests, first_block };

        // Extend the ExecutionOutcome object by itself.
        exec_res.extend(exec_res.clone());

        // Assert the extended ExecutionOutcome matches the expected outcome.
        assert_eq!(
            exec_res,
            ExecutionOutcome {
                bundle: Default::default(),
                receipts: vec![vec![Some(receipt.clone())], vec![Some(receipt)]],
                requests: vec![Requests::new(vec![request.clone()]), Requests::new(vec![request])],
                first_block: 123,
            }
        );
    }

    #[test]
    fn test_split_at_execution_outcome() {
        // Create a random receipt object
        let receipt = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![
            vec![Some(receipt.clone())],
            vec![Some(receipt.clone())],
            vec![Some(receipt.clone())],
        ];

        // Define the first block number
        let first_block = 123;

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests = vec![
            Requests::new(vec![request.clone()]),
            Requests::new(vec![request.clone()]),
            Requests::new(vec![request.clone()]),
        ];

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res =
            ExecutionOutcome { bundle: Default::default(), receipts, requests, first_block };

        // Split the ExecutionOutcome at block number 124
        let result = exec_res.clone().split_at(124);

        // Define the expected lower ExecutionOutcome after splitting
        let lower_execution_outcome = ExecutionOutcome {
            bundle: Default::default(),
            receipts: vec![vec![Some(receipt.clone())]],
            requests: vec![Requests::new(vec![request.clone()])],
            first_block,
        };

        // Define the expected higher ExecutionOutcome after splitting
        let higher_execution_outcome = ExecutionOutcome {
            bundle: Default::default(),
            receipts: vec![vec![Some(receipt.clone())], vec![Some(receipt)]],
            requests: vec![Requests::new(vec![request.clone()]), Requests::new(vec![request])],
            first_block: 124,
        };

        // Assert that the split result matches the expected lower and higher outcomes
        assert_eq!(result.0, Some(lower_execution_outcome));
        assert_eq!(result.1, higher_execution_outcome);

        // Assert that splitting at the first block number returns None for the lower outcome
        assert_eq!(exec_res.clone().split_at(123), (None, exec_res));
    }

    #[test]
    fn all_environment_paths_preserve_exact_timestamps_during_execution() {
        use reth_evm::ConfigureEngineEvm;
        use reth_primitives_traits::SealedBlock;
        use revm::state::Bytecode;

        let config = SeismicEvmConfig::new(
            reth_seismic_chainspec::SEISMIC_DEV.clone(),
            Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())),
        );
        let seconds = 1_800_000_000;
        let contract = Address::with_last_byte(0xbb);
        // Return TIMESTAMP and TIMESTAMPMS as two ABI words.
        let code = Bytecode::new_raw(bytes!("426000524b60205260406000f3"));

        for part in [0, 123, 999] {
            let header = SeismicHeader {
                inner: Header {
                    timestamp: seconds,
                    number: 1,
                    blob_gas_used: Some(0),
                    ..exec_header()
                },
                timestamp_millis_part: part,
            };
            let parent = SeismicHeader::from(Header {
                timestamp: seconds - 1,
                blob_gas_used: Some(0),
                base_fee_per_gas: Some(INITIAL_BASE_FEE),
                ..exec_header()
            });
            let attributes = SeismicNextBlockEnvAttributes {
                inner: NextBlockEnvAttributes {
                    timestamp: seconds,
                    suggested_fee_recipient: Address::ZERO,
                    prev_randao: B256::ZERO,
                    gas_limit: header.gas_limit(),
                    parent_beacon_block_root: None,
                    withdrawals: None,
                },
                timestamp_millis_part: part,
            };
            let payload =
                SeismicExecutionData::from_sealed_block(SealedBlock::seal_slow(SeismicBlock {
                    header: header.clone(),
                    ..Default::default()
                }));
            let environments = [
                config.evm_env(&header),
                config.next_evm_env(&parent, &attributes).unwrap(),
                config.evm_env_for_payload(&payload),
            ];

            for (path, env) in environments.into_iter().enumerate() {
                assert_eq!(env.block_env.timestamp, U256::from(seconds), "path {path}");
                assert_eq!(env.block_env.timestamp_millis_part, part, "path {path}");
                assert!(env.block_env.blob_excess_gas_and_price.is_some(), "path {path}");
                for inspected in [false, true] {
                    for system_call in [false, true] {
                        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
                        let caller = funded_caller(&mut db);
                        db.insert_account_info(
                            contract,
                            AccountInfo {
                                nonce: 1,
                                code_hash: code.hash_slow(),
                                code: Some(code.clone()),
                                ..Default::default()
                            },
                        );
                        let mut evm = if inspected {
                            config.evm_with_env_and_inspector(db, env.clone(), NoOpInspector)
                        } else {
                            config.evm_with_env(db, env.clone())
                        };
                        let outcome = if system_call {
                            evm.transact_system_call(caller, contract, Default::default())
                        } else {
                            let mut tx = transfer_tx(caller, Some(env.cfg_env.chain_id));
                            tx.base.gas_limit = 100_000;
                            tx.base.gas_price = u128::from(env.block_env.basefee);
                            evm.transact(tx)
                        }
                        .unwrap();
                        assert!(outcome.result.is_success());
                        let mut words = outcome.result.output().unwrap().chunks_exact(32);
                        assert_eq!(U256::from_be_slice(words.next().unwrap()), U256::from(seconds));
                        assert_eq!(
                            U256::from_be_slice(words.next().unwrap()),
                            U256::from(seconds * 1000 + part)
                        );
                        assert!(words.next().is_none());
                        let (_, finished) = evm.finish();
                        assert_eq!(finished.block_env.timestamp_millis_part, part);
                        assert_eq!(finished.block_env.timestamp, U256::from(seconds));
                    }
                }
            }
        }
    }

    /// A funded EOA used as the transaction sender in chain-ID tests.
    fn funded_caller(db: &mut CacheDB<EmptyDBTyped<ProviderError>>) -> Address {
        let caller = Address::with_last_byte(0xaa);
        db.insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(10u128.pow(18)),
                nonce: 0,
                code_hash: Default::default(),
                code: None,
            },
        );
        caller
    }

    /// Builds a minimal legacy value-transfer transaction with the given `chain_id`.
    fn transfer_tx(caller: Address, chain_id: Option<u64>) -> SeismicTransaction<TxEnv> {
        SeismicTransaction {
            base: TxEnv {
                caller,
                gas_limit: 21_000,
                gas_price: 0,
                gas_priority_fee: None,
                kind: TxKind::Call(Address::with_last_byte(0xbb)),
                value: U256::ZERO,
                data: Default::default(),
                chain_id,
                nonce: 0,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: 0,
                authorization_list: Default::default(),
                // Legacy tx type: it is the only type permitted to omit `chain_id`.
                tx_type: 0,
            },
            tx_hash: Default::default(),
            decryption_failed: false,
            signed_read: false,
            gas_payment: seismic_revm::GasPayment::Auto,
        }
    }

    /// Header that makes [`SeismicEvmConfig::evm_env`] produce a valid post-Cancun
    /// block env (Seismic genesis activates at Mercury, which is post-Cancun, so the
    /// block env requires an excess-blob-gas value to be set).
    fn exec_header() -> Header {
        Header { excess_blob_gas: Some(0), gas_limit: 30_000_000, ..Default::default() }
    }

    /// Regression test for the block-import chain-ID bypass (audit finding).
    ///
    /// The txpool rejects transactions whose embedded chain ID differs from the
    /// configured chain, but block execution runs through the EVM env produced by
    /// [`SeismicEvmConfig`]. A block imported via `engine_newPayload` does not pass
    /// through the local txpool, so the chain-ID invariant must also hold at the
    /// execution boundary — otherwise a Byzantine proposer can smuggle a wrong-chain
    /// transaction into a canonical block.
    #[test]
    fn wrong_chain_id_tx_is_rejected_at_execution() {
        let evm_config = test_evm_config();
        let chain_id = SEISMIC_MAINNET.chain().id();

        // Use the production EVM env construction (same path as block import).
        let evm_env = evm_config.evm_env(&SeismicHeader::from(exec_header()));
        assert_eq!(evm_env.cfg_env.chain_id, chain_id);

        // A transaction validly signed for a *different* chain must be rejected.
        let wrong_chain_id = chain_id + 1;
        let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        let caller = funded_caller(&mut db);
        let mut evm = evm_config.evm_with_env(db, evm_env);

        let result = evm.transact(transfer_tx(caller, Some(wrong_chain_id)));

        assert!(
            matches!(result, Err(EVMError::Transaction(InvalidTransaction::InvalidChainId))),
            "wrong-chain transaction must be rejected at execution, got: {result:?}"
        );
    }

    /// Complements the rejection test: a transaction carrying the correct chain ID
    /// (or, for legacy transactions, omitting it entirely per EIP-155) must still
    /// execute, so enabling the chain-ID check does not break legitimate traffic.
    #[test]
    fn matching_and_absent_chain_id_txs_are_accepted() {
        let evm_config = test_evm_config();
        let chain_id = SEISMIC_MAINNET.chain().id();

        for tx_chain_id in [Some(chain_id), None] {
            let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
            let caller = funded_caller(&mut db);
            let mut evm = evm_config
                .evm_with_env(db, evm_config.evm_env(&SeismicHeader::from(exec_header())));

            let result = evm.transact(transfer_tx(caller, tx_chain_id));

            assert!(
                result.is_ok(),
                "legitimate transaction (chain_id={tx_chain_id:?}) must execute, got: {result:?}"
            );
        }
    }
}
