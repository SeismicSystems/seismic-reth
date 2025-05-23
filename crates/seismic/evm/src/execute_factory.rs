use crate::{EthBlockExecutionCtx, SeismicBlockExecutor};
use alloy_consensus::{Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::{
        receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder},
        spec::{EthExecutorSpec, EthSpec},
    },
    Database, EvmFactory, FromRecoveredTx,
};
use alloy_primitives::Log;
use alloy_seismic_evm::SeismicEvmFactory;
use revm::{database::State, Inspector};

/// Seismic block executor factory.
#[derive(Debug, Clone, Default, Copy)]
pub struct SeismicBlockExecutorFactory<
    R = AlloyReceiptBuilder,
    Spec = EthSpec,
    EvmFactory = SeismicEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
}

impl<R, Spec, EvmFactory> SeismicBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`ReceiptBuilder`].
    pub const fn new(receipt_builder: R, spec: Spec, evm_factory: EvmFactory) -> Self {
        Self { receipt_builder, spec, evm_factory }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Exposes the EVM factory.
    pub const fn evm_factory(&self) -> &EvmFactory {
        &self.evm_factory
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for SeismicBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    Spec: EthExecutorSpec,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction>>,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmF::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<EvmF::Context<&'a mut State<DB>>> + 'a,
    {
        // From alloy_evm::eth::block
        // EthBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder)
        SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder)
    }
}
