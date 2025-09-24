//! Loads and formats Seismic receipt RPC response.

use reth_node_api::NodePrimitives;
use reth_rpc_eth_api::{
    helpers::LoadReceipt, transaction::ConvertReceiptInput, RpcConvert, RpcNodeCore,
};
use reth_rpc_eth_types::{receipt::build_receipt, EthApiError};
use reth_seismic_primitives::SeismicReceipt;
use seismic_alloy_consensus::SeismicReceiptEnvelope;
use seismic_alloy_network::{foundry::tx_request::SeismicTransaction, SeismicReth};
use seismic_alloy_rpc_types::SeismicTransactionReceipt;
use std::fmt::Debug;

use crate::{SeismicEthApi, SeismicEthApiError};

impl<N, Rpc> LoadReceipt for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Network = SeismicReth, Error = SeismicEthApiError>,
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
    pub fn new<N>(input: ConvertReceiptInput<'_, N>) -> Result<Self, EthApiError>
    where
        N: NodePrimitives<SignedTx = SeismicTransaction, Receipt = SeismicReceipt>,
    {
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
