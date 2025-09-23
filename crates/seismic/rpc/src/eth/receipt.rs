//! Loads and formats Seismic receipt RPC response.

use std::{any::Any, fmt::Debug};

use alloy_consensus::transaction::TransactionMeta;
use alloy_eips::eip7840::BlobParams;
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec};
use reth_node_api::{FullNodeComponents, NodePrimitives, NodeTypes};
use reth_rpc_eth_api::{
    helpers::LoadReceipt,
    transaction::{ConvertReceiptInput, ReceiptConverter},
    FromEthApiError, RpcConvert, RpcNodeCore, RpcReceipt,
};
use reth_rpc_eth_types::{receipt::build_receipt, EthApiError};
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use reth_storage_api::{ReceiptProvider, TransactionsProvider};
use seismic_alloy_consensus::{SeismicReceiptEnvelope, SeismicTxType};
use seismic_alloy_network::{foundry::tx_request::SeismicTransaction, SeismicReth};
use seismic_alloy_rpc_types::SeismicTransactionReceipt;

use crate::{SeismicEthApi, SeismicEthApiError};

impl<N, Rpc> LoadReceipt for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Network = SeismicReth, Error = SeismicEthApiError>,
{
}

/*
    async fn build_transaction_receipt(
        &self,
        tx: SeismicTransactionSigned,
        meta: TransactionMeta,
        receipt: SeismicReceipt,
    ) -> Result<RpcReceipt<Self::NetworkTypes>, Self::Error> {
        let hash = meta.block_hash;
        // get all receipts for the block
        let all_receipts = self
            .inner
            .cache()
            .get_receipts(hash)
            .await
            .map_err(Self::Error::from_eth_err)?
            .ok_or(EthApiError::HeaderNotFound(hash.into()))?;
        let blob_params = self.provider().chain_spec().blob_params_at_timestamp(meta.timestamp);

        Ok(SeismicReceiptBuilder::new(&tx, meta, &receipt, &all_receipts, blob_params)?.build())
    }
*/

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
