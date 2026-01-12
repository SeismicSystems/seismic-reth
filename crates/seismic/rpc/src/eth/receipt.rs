//! Loads and formats Seismic receipt RPC response.

use reth_rpc_convert::transaction::{ConvertReceiptInput, ReceiptConverter};
use reth_rpc_eth_api::{helpers::LoadReceipt, RpcConvert, RpcNodeCore};
use reth_rpc_eth_types::{receipt::build_receipt, EthApiError};
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
        let base = build_receipt(&input, None, |receipt_with_bloom| match input.receipt.as_ref() {
            SeismicReceipt::Legacy(_) => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
            SeismicReceipt::Eip2930(_) => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
            SeismicReceipt::Eip1559(_) => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
            SeismicReceipt::Eip7702(_) => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
            SeismicReceipt::Seismic(_) => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
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
