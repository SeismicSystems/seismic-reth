#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_evm::IntoTxEnv;
use alloy_evm::{Database, Evm, EvmEnv, EvmFactory};
use alloy_primitives::address;
use alloy_primitives::{Address, Bytes};
use seismic_revm::DefaultSeismic;
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use revm::{
    context::{BlockEnv, Cfg, TxEnv},
    context_interface::result::{EVMError, ResultAndState},
    context_interface::ContextTr,
    handler::EthPrecompiles,
    handler::PrecompileProvider,
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    precompile::{PrecompileFn, PrecompileOutput, PrecompileResult, Precompiles},
    primitives::hardfork::SpecId,
    Context, Inspector, InspectEvm,
};
use std::sync::OnceLock;
use seismic_revm::{SeismicContext, SeismicSpecId};
use revm::ExecuteEvm;
use seismic_revm::SeismicHaltReason;
use seismic_revm::transaction::abstraction::SeismicTransaction;
use seismic_revm::SeismicBuilder;
use alloy_primitives::{B256, U256};
use alloy_primitives::TxKind;
use seismic_revm::transaction::abstraction::RngMode;


/// Seismic EVM implementation.
///
/// This is a wrapper type around the `revm` evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`SeismicEvm`](seismic_revm::SeismicEvm) type.
#[allow(missing_debug_implementations)]
pub struct SeismicEvm<DB: Database, I> {
    inner: seismic_revm::SeismicEvm<SeismicContext<DB>, I>,
    inspect: bool,
}

impl<DB: Database + revm::database_interface::Database, I> SeismicEvm<DB, I> {
    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &SeismicContext<DB> {
        &self.inner.0.data.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut SeismicContext<DB> {
        &mut self.inner.0.data.ctx
    }

    /// Provides a mutable reference to the EVM inspector.
    pub fn inspector_mut(&mut self) -> &mut I {
        &mut self.inner.0.data.inspector
    }
}

impl<DB: Database, I> SeismicEvm<DB, I> {
    /// creates a new [`SeismicEvm`].
    pub fn new(inner: seismic_revm::SeismicEvm<SeismicContext<DB>, I>, inspect: bool,
    ) -> Self {
        Self { inner, inspect }
    }
}

impl<DB: Database, I> Deref for SeismicEvm<DB, I> {
    type Target = SeismicContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I> DerefMut for SeismicEvm<DB, I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I> Evm for SeismicEvm<DB, I>
where
    DB: Database,
    I: Inspector<SeismicContext<DB>>,
    // PRECOMPILE: PrecompileProvider<EthEvmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = SeismicTransaction<TxEnv>;
    type Error = EVMError<DB::Error>;
    type HaltReason = SeismicHaltReason;
    type Spec = SeismicSpecId;

    fn block(&self) -> &BlockEnv {
        self.inner.0.block()
    }

    fn transact_raw(&mut self, tx: Self::Tx) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.set_tx(tx);
            self.inner.inspect_replay()
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact(
        &mut self,
        tx: impl IntoTxEnv<Self::Tx>,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        // attention: ENCRYPT and DECRYPT HERE
        self.transact_raw(tx.into_tx_env())
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        let tx = SeismicTransaction {
            base: TxEnv {
                caller,
                kind: TxKind::Call(contract),
                // Explicitly set nonce to 0 so revm does not do any nonce checks
                nonce: 0,
                gas_limit: 30_000_000,
                value: U256::ZERO,
                data,
                // Setting the gas price to zero enforces that no value is transferred as part of
                // the call, and that the call will not count against the block's
                // gas limit
                gas_price: 0,
                // The chain ID check is not relevant here and is disabled if set to None
                chain_id: None,
                // Setting the gas priority fee to None ensures the effective gas price is derived
                // from the `gas_price` field, which we need to be zero
                gas_priority_fee: None,
                access_list: Default::default(),
                // blob fields can be None for this tx
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
                tx_type: 0,
                authorization_list: Default::default(),
            },
            tx_hash: B256::ZERO,
            rng_mode: RngMode::Execution,
        };

        let mut gas_limit = tx.base.gas_limit;
        let mut basefee = 0;
        let mut disable_nonce_check = true;

        // ensure the block gas limit is >= the tx
        core::mem::swap(&mut self.block.gas_limit, &mut gas_limit);
        // disable the base fee check for this call by setting the base fee to zero
        core::mem::swap(&mut self.block.basefee, &mut basefee);
        // disable the nonce check
        core::mem::swap(&mut self.cfg.disable_nonce_check, &mut disable_nonce_check);

        let mut res = self.transact(tx);

        // swap back to the previous gas limit
        core::mem::swap(&mut self.block.gas_limit, &mut gas_limit);
        // swap back to the previous base fee
        core::mem::swap(&mut self.block.basefee, &mut basefee);
        // swap back to the previous nonce check flag
        core::mem::swap(&mut self.cfg.disable_nonce_check, &mut disable_nonce_check);

        // NOTE: We assume that only the contract storage is modified. Revm currently marks the
        // caller and block beneficiary accounts as "touched" when we do the above transact calls,
        // and includes them in the result.
        //
        // We're doing this state cleanup to make sure that changeset only includes the changed
        // contract storage.
        if let Ok(res) = &mut res {
            res.state.retain(|addr, _| *addr == contract);
        }

        res
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        &mut self.journaled_state.database
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context { block: block_env, cfg: cfg_env, journaled_state, .. } = self.inner.0.data.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }
}

/// Custom EVM configuration.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SeismicEvmFactory;

impl EvmFactory for SeismicEvmFactory {
    type Evm<DB: Database, I: Inspector<SeismicContext<DB>>> = SeismicEvm<DB, I>;
    type Tx = SeismicTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = SeismicHaltReason;
    type Context<DB: Database> = SeismicContext<DB>;
    type Spec = SeismicSpecId;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv<SeismicSpecId>) -> Self::Evm<DB, NoOpInspector> {
        SeismicEvm {
            inner: Context::seismic()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_seismic_with_inspector(NoOpInspector {}),
            inspect: false,
        }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        SeismicEvm {
            inner: Context::seismic()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_seismic_with_inspector(inspector),
            inspect: true,
        }
    }
}