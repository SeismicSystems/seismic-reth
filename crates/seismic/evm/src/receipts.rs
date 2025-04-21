use alloy_consensus::{Eip658Value, Receipt};
use alloy_evm::eth::receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx};
use reth_evm::Evm;
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use seismic_alloy_consensus::SeismicTxType;

/// A builder that operates on seismic-reth primitive types, specifically
/// [`SeismicTransactionSigned`] and [`SeismicReceipt`].
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicReceiptBuilder;

impl ReceiptBuilder for SeismicReceiptBuilder {
    type Transaction = SeismicTransactionSigned;
    type Receipt = SeismicReceipt;

    fn build_receipt<'a, E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'a, SeismicTransactionSigned, E>,
    ) -> Result<Self::Receipt, ReceiptBuilderCtx<'a, SeismicTransactionSigned, E>> {
        match ctx.tx.tx_type() {
            ty => {
                let receipt = Receipt {
                    // Success flag was added in `EIP-658: Embedding transaction status code in
                    // receipts`.
                    status: Eip658Value::Eip658(ctx.result.is_success()),
                    cumulative_gas_used: ctx.cumulative_gas_used,
                    logs: ctx.result.into_logs(),
                };

                Ok(match ty {
                    SeismicTxType::Legacy => SeismicReceipt::Legacy(receipt),
                    SeismicTxType::Eip1559 => SeismicReceipt::Eip1559(receipt),
                    SeismicTxType::Eip2930 => SeismicReceipt::Eip2930(receipt),
                    SeismicTxType::Eip7702 => SeismicReceipt::Eip7702(receipt),
                    SeismicTxType::Seismic => SeismicReceipt::Seismic(receipt),
                })
            }
        }
    }
}
