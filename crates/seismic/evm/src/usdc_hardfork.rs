//! The Venus hardfork: a one-shot bytecode replacement for the USDC contract.
//!
//! Venus is an *irregular state transition* modelled on Optimism's Canyon create2-deployer
//! force-deploy: at the fork-activation block the block executor directly rewrites the code (and
//! code hash) of a single account, before any of the block's transactions run, so every node
//! converges on the same post-fork state root.
//!
//! The executor keys the swap off the [`SEISMIC_VENUS_BLOCK`] constant directly, firing when the
//! block number equals it. This is deliberately independent of the chainspec fork schedule so the
//! swap triggers regardless of how the chain was launched — including from a genesis JSON file,
//! which bypasses the built-in Seismic fork schedule entirely. The swap therefore fires exactly
//! once; every other block costs a single integer comparison and performs no state access.
//!
//! (The fork is *also* registered in the built-in chain specs so it participates in fork-id / p2p
//! partitioning for nodes launched from those specs, but that registration is not what triggers
//! the swap.)

use alloc::format;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, CommitChanges, ExecutableTx, OnStateHook,
    },
    Database, Evm, EvmFactory,
};
use alloy_primitives::{address, keccak256, Address, Bytes};
use reth_seismic_forks::SEISMIC_VENUS_BLOCK;
use revm::{
    context::result::ExecutionResult,
    database::State,
    primitives::HashMap,
    state::{Account, Bytecode},
    DatabaseCommit, Inspector,
};

/// Address of the testnet USDC contract whose bytecode the Venus hardfork replaces.
const USDC_ADDRESS: Address = address!("0x790701048922e265105fd6a4467a2901c2201c43");

/// The replacement runtime bytecode for [`USDC_ADDRESS`], embedded as a `0x`-prefixed hex string.
const USDC_BYTECODE_HEX: &str = include_str!("../res/usdc_hardfork_bytecode.txt");

/// Force-replaces the code of [`USDC_ADDRESS`] with the Venus bytecode.
///
/// Mirrors the shape of Optimism's `ensure_create2_deployer`: load the account, overwrite its code
/// and code hash, mark it touched, and commit it so the change flows into the bundle state, the
/// state root, and the `Bytecodes` table through the normal execution path. Balance, nonce and
/// storage are preserved.
fn apply_venus_usdc_swap<DB>(db: &mut State<DB>) -> Result<(), BlockExecutionError>
where
    DB: Database,
{
    // Decode the embedded bytecode. A malformed blob is a build error; the accompanying unit test
    // decodes it so CI fails long before this runs, but propagate rather than panic to satisfy the
    // crate's strict lints.
    let trimmed = USDC_BYTECODE_HEX.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let raw: Bytes = alloy_primitives::hex::decode(hex)
        .map_err(|err| {
            BlockExecutionError::msg(format!("Venus: invalid USDC bytecode hex: {err}"))
        })?
        .into();

    // The account code hash is keccak256 of the runtime bytecode.
    let code_hash = keccak256(&raw);
    let bytecode = Bytecode::new_raw(raw);

    let account = db.load_cache_account(USDC_ADDRESS).map_err(|err| {
        BlockExecutionError::msg(format!(
            "Venus: failed to load USDC account {USDC_ADDRESS}: {err}"
        ))
    })?;

    let mut info = account.account_info().unwrap_or_default();
    info.code_hash = code_hash;
    info.code = Some(bytecode);

    let mut revm_account: Account = info.into();
    revm_account.mark_touch();

    db.commit(HashMap::from_iter([(USDC_ADDRESS, revm_account)]));
    Ok(())
}

/// A [`BlockExecutorFactory`] wrapper that layers the Venus USDC bytecode swap onto an inner
/// factory's executors, without otherwise changing execution.
#[derive(Debug, Clone)]
pub struct VenusBlockExecutorFactory<Inner> {
    inner: Inner,
}

impl<Inner> VenusBlockExecutorFactory<Inner> {
    /// Creates a new [`VenusBlockExecutorFactory`] wrapping `inner`.
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }

    /// Returns the wrapped inner factory.
    pub const fn inner(&self) -> &Inner {
        &self.inner
    }
}

impl<Inner> BlockExecutorFactory for VenusBlockExecutorFactory<Inner>
where
    Inner: BlockExecutorFactory,
{
    type EvmFactory = Inner::EvmFactory;
    type ExecutionCtx<'a> = Inner::ExecutionCtx<'a>;
    type Transaction = Inner::Transaction;
    type Receipt = Inner::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <Self::EvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        VenusBlockExecutor { inner: self.inner.create_executor(evm, ctx) }
    }
}

/// A [`BlockExecutor`] wrapper that applies the Venus USDC bytecode swap in
/// [`apply_pre_execution_changes`](BlockExecutor::apply_pre_execution_changes) at the activation
/// block and otherwise delegates to the inner executor.
#[derive(Debug)]
pub struct VenusBlockExecutor<Ex> {
    inner: Ex,
}

impl<'db, DB, Ex> BlockExecutor for VenusBlockExecutor<Ex>
where
    DB: Database + 'db,
    Ex: BlockExecutor<Evm: Evm<DB = &'db mut State<DB>>>,
{
    type Transaction = Ex::Transaction;
    type Receipt = Ex::Receipt;
    type Evm = Ex::Evm;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        let block_number: u64 = self.inner.evm().block().number.saturating_to();

        // Fire exactly once, at the activation block, keyed off the block number directly so the
        // swap triggers regardless of how the chain was launched (built-in spec or genesis JSON).
        if block_number == SEISMIC_VENUS_BLOCK {
            apply_venus_usdc_swap(&mut **self.inner.evm_mut().db_mut())?;
        }

        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        self.inner.execute_transaction_with_commit_condition(tx, f)
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        self.inner.execute_transaction_with_result_closure(tx, f)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// The embedded bytecode must be valid hex; this guards against a malformed blob reaching the
    /// activation block, where a decode failure would break block execution for every node.
    #[test]
    fn embedded_usdc_bytecode_decodes() {
        let trimmed = USDC_BYTECODE_HEX.trim();
        let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let raw = alloy_primitives::hex::decode(hex).unwrap();
        assert!(!raw.is_empty(), "USDC bytecode must not be empty");
        // Sanity check: the account code hash is keccak256 of the runtime bytecode.
        let _ = keccak256(&raw);
    }

    #[test]
    fn activation_block_is_the_expected_block() {
        // The executor fires the swap when the block number equals this constant.
        assert_eq!(SEISMIC_VENUS_BLOCK, 39_307_813);
    }

    #[test]
    fn swap_writes_new_code_and_matching_hash() {
        use revm::database::{InMemoryDB, StateBuilder};

        let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
        apply_venus_usdc_swap(&mut state).unwrap();

        let trimmed = USDC_BYTECODE_HEX.trim();
        let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let raw = alloy_primitives::hex::decode(hex).unwrap();

        let account = state.load_cache_account(USDC_ADDRESS).unwrap();
        let info = account.account_info().expect("USDC account must exist after the swap");

        assert_eq!(info.code_hash, keccak256(&raw), "code hash must be keccak256 of the new code");
        let code = info.code.expect("code must be set after the swap");
        assert_eq!(code.original_bytes().as_ref(), raw.as_slice(), "stored code must match");
    }
}
