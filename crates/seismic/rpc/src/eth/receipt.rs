//! Loads and formats Seismic receipt RPC response.

use alloy_consensus::Typed2718;
use reth_rpc_convert::transaction::{ConvertReceiptInput, ReceiptConverter};
use reth_rpc_eth_api::{helpers::LoadReceipt, RpcConvert, RpcNodeCore};
use reth_rpc_eth_types::{receipt::build_receipt, EthApiError};
use reth_rpc_server_types::result::internal_rpc_err;
use reth_seismic_primitives::{SeismicPrimitives, SeismicReceipt};
use seismic_alloy_consensus::SeismicReceiptEnvelope;
use seismic_alloy_rpc_types::SeismicTransactionReceipt;
use std::fmt::Debug;

use crate::{SeismicEthApi, SeismicEthApiError};

impl<N, Rpc> LoadReceipt for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
}

/// Builds an [`SeismicTransactionReceipt`].
///
/// Like [`EthReceiptBuilder`], but with Seismic types
#[derive(Debug)]
pub struct SeismicReceiptBuilder {
    /// The base response body, contains L1 fields.
    pub base: SeismicTransactionReceipt,
}

impl SeismicReceiptBuilder {
    /// Returns a new builder.
    pub fn new(input: ConvertReceiptInput<'_, SeismicPrimitives>) -> Result<Self, EthApiError> {
        // The receipt and its transaction must agree on the transaction type.
        let receipt_ty = input.receipt.tx_type() as u8;
        let tx_ty = input.tx.ty();
        if receipt_ty != tx_ty {
            return Err(EthApiError::other(internal_rpc_err(format!(
                "receipt type {receipt_ty} does not match transaction type {tx_ty}"
            ))));
        }

        let base = build_receipt(&input, None, |receipt_with_bloom| match input.receipt.as_ref() {
            SeismicReceipt::Legacy(_) => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
            SeismicReceipt::Eip2930(_) => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
            SeismicReceipt::Eip1559(_) => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
            SeismicReceipt::Eip7702(_) => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
            SeismicReceipt::Seismic(_) => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
            SeismicReceipt::Eip4844(_) => SeismicReceiptEnvelope::Eip4844(receipt_with_bloom),
        });

        Ok(Self { base })
    }

    /// Builds [`SeismicTransactionReceipt`] by combing core (l1) receipt fields and additional
    /// Seismic receipt fields.
    pub fn build(self) -> SeismicTransactionReceipt {
        self.base
    }
}

/// Seismic receipt converter.
#[derive(Debug, Clone)]
pub struct SeismicReceiptConverter;

impl Default for SeismicReceiptConverter {
    fn default() -> Self {
        Self::new()
    }
}

impl SeismicReceiptConverter {
    /// Creates a new seismic receipt converter.
    pub const fn new() -> Self {
        Self
    }
}

impl ReceiptConverter<SeismicPrimitives> for SeismicReceiptConverter {
    type Error = SeismicEthApiError;
    type RpcReceipt = SeismicTransactionReceipt;

    fn convert_receipts(
        &self,
        inputs: Vec<ConvertReceiptInput<'_, SeismicPrimitives>>,
    ) -> Result<Vec<Self::RpcReceipt>, Self::Error> {
        inputs
            .into_iter()
            .map(|input| {
                SeismicReceiptBuilder::new(input)
                    .map_err(SeismicEthApiError::Eth)
                    .map(|builder| builder.build())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{
        transaction::{Recovered, TransactionMeta},
        Eip658Value, Receipt,
    };
    use alloy_primitives::{Address, B256};
    use reth_seismic_primitives::test_utils::get_signed_seismic_tx;
    use std::borrow::Cow;

    #[test]
    fn new_rejects_mismatched_receipt_and_tx_types() {
        // Seismic-typed transaction paired with a legacy-typed receipt.
        let tx = get_signed_seismic_tx(B256::ZERO);
        let receipt = SeismicReceipt::Legacy(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 0,
            logs: Vec::new(),
        });
        let input = ConvertReceiptInput {
            receipt: Cow::Owned(receipt),
            tx: Recovered::new_unchecked(&tx, Address::ZERO),
            gas_used: 0,
            next_log_index: 0,
            meta: TransactionMeta::default(),
        };
        assert!(SeismicReceiptBuilder::new(input).is_err());
    }
}
