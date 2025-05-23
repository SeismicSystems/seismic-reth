use alloy_consensus::{Eip658Value, Receipt};
use alloy_evm::eth::receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx};
use reth_evm::Evm;
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use seismic_alloy_consensus::SeismicTxType;

/// A builder that operates on seismic-reth primitive types, specifically
/// [`SeismicTransactionSigned`] and [`SeismicReceipt`].
/// 
/// Why is this different than SeismicAlloyReceiptBuilder in seismic-evm? Can we reuse code?
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicRethReceiptBuilder;

impl ReceiptBuilder for SeismicRethReceiptBuilder {
    type Transaction = SeismicTransactionSigned;
    type Receipt = SeismicReceipt;

    fn build_receipt<E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'_, SeismicTransactionSigned, E>,
    ) -> Self::Receipt {
        match ctx.tx.tx_type() {
            ty => {
                let receipt = Receipt {
                    status: Eip658Value::Eip658(ctx.result.is_success()),
                    cumulative_gas_used: ctx.cumulative_gas_used,
                    logs: ctx.result.into_logs(),
                };

                match ty {
                    SeismicTxType::Legacy => SeismicReceipt::Legacy(receipt),
                    SeismicTxType::Eip1559 => SeismicReceipt::Eip1559(receipt),
                    SeismicTxType::Eip2930 => SeismicReceipt::Eip2930(receipt),
                    SeismicTxType::Eip7702 => SeismicReceipt::Eip7702(receipt),
                    SeismicTxType::Seismic => SeismicReceipt::Seismic(receipt),
                }
            }
        }
    }
}
