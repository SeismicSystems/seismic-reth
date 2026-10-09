//! Seismic block execution context and next-block attributes.
//!
//! Both wrap their stock Ethereum counterparts and add the sub-second component of the block
//! timestamp, which the block assembler needs to produce a [`SeismicHeader`].

use alloy_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::EthBlockExecutionCtx,
    Database, EvmFactory,
};
use reth_evm::NextBlockEnvAttributes;
#[cfg(feature = "rpc")]
use reth_seismic_primitives::SeismicHeader;
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use revm::{database::State, Inspector};

use crate::{SeismicBlockExecutorFactory, SeismicEvmFactory, SeismicRethReceiptBuilder};
use reth_seismic_chainspec::SeismicChainSpec;
use std::sync::Arc;

/// Execution context for a Seismic block.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct SeismicBlockExecutionCtx<'a> {
    /// The stock Ethereum execution context.
    #[deref]
    pub inner: EthBlockExecutionCtx<'a>,
    /// Sub-second (milliseconds) component of the block timestamp, `0..1000`.
    pub timestamp_millis_part: u64,
}

/// Attributes for the next block's environment.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct SeismicNextBlockEnvAttributes {
    /// The stock attributes. `timestamp` is in Unix seconds.
    #[deref]
    pub inner: NextBlockEnvAttributes,
    /// Sub-second (milliseconds) component of the block timestamp, `0..1000`.
    pub timestamp_millis_part: u64,
}

impl SeismicNextBlockEnvAttributes {
    /// Returns the block time in Unix milliseconds.
    pub const fn timestamp_millis(&self) -> u64 {
        self.inner
            .timestamp
            .saturating_mul(reth_seismic_primitives::MILLIS_PER_SECOND)
            .saturating_add(self.timestamp_millis_part)
    }
}

impl From<NextBlockEnvAttributes> for SeismicNextBlockEnvAttributes {
    /// Wraps stock attributes with a zero sub-second component.
    fn from(inner: NextBlockEnvAttributes) -> Self {
        Self { inner, timestamp_millis_part: 0 }
    }
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<SeismicHeader>
    for SeismicNextBlockEnvAttributes
{
    fn build_pending_env(parent: &reth_primitives_traits::SealedHeader<SeismicHeader>) -> Self {
        // The stock builder advances the parent's seconds timestamp by one slot; the pending
        // block keeps the parent's sub-second component.
        Self {
            inner: NextBlockEnvAttributes::build_pending_env(parent),
            timestamp_millis_part: parent.timestamp_millis_part,
        }
    }
}

/// The block executor factory used by the Seismic node.
///
/// Wraps the fork's [`SeismicBlockExecutorFactory`] so the execution context can carry the
/// sub-second timestamp component the assembler needs. Execution itself is delegated unchanged.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct SeismicRethBlockExecutorFactory {
    /// The wrapped factory.
    #[deref]
    pub inner: SeismicBlockExecutorFactory<
        SeismicRethReceiptBuilder,
        Arc<SeismicChainSpec>,
        SeismicEvmFactory,
    >,
}

impl SeismicRethBlockExecutorFactory {
    /// Wraps the given factory.
    pub const fn new(
        inner: SeismicBlockExecutorFactory<
            SeismicRethReceiptBuilder,
            Arc<SeismicChainSpec>,
            SeismicEvmFactory,
        >,
    ) -> Self {
        Self { inner }
    }
}

impl BlockExecutorFactory for SeismicRethBlockExecutorFactory {
    type EvmFactory = SeismicEvmFactory;
    type ExecutionCtx<'a> = SeismicBlockExecutionCtx<'a>;
    type Transaction = SeismicTransactionSigned;
    type Receipt = SeismicReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <SeismicEvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<<SeismicEvmFactory as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        self.inner.create_executor(evm, ctx.inner)
    }
}
