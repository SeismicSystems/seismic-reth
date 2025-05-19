//! Loads and formats Seismic receipt RPC response.

use alloy_consensus::transaction::TransactionMeta;
use alloy_eips::{eip2718::Encodable2718, eip7840::BlobParams};
use alloy_rpc_types_eth::{Log, TransactionReceipt};
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_rpc_eth_api::{helpers::LoadReceipt, FromEthApiError, RpcReceipt};
use reth_rpc_eth_types::{receipt::build_receipt, EthApiError};
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use reth_storage_api::{ReceiptProvider, TransactionsProvider};
use seismic_alloy_consensus::{SeismicReceiptEnvelope, SeismicTxType};
use seismic_alloy_rpc_types::SeismicTransactionReceipt;
use reth_rpc_eth_api::RpcNodeCore;

use crate::SeismicEthApi;

impl<N> LoadReceipt for SeismicEthApi<N>
where
    Self: Send + Sync,
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = ChainSpec>>,
    Self::Provider: TransactionsProvider<Transaction = SeismicTransactionSigned>
        + ReceiptProvider<Receipt = SeismicReceipt>
        + ChainSpecProvider<ChainSpec = ChainSpec>,
{
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
    pub fn new(
        transaction: &SeismicTransactionSigned,
        meta: TransactionMeta,
        receipt: &SeismicReceipt,
        all_receipts: &[SeismicReceipt],
        blob_params: Option<BlobParams>,
    ) -> Result<Self, EthApiError> {
        let base = build_receipt(
            transaction,
            meta,
            receipt,
            all_receipts,
            blob_params,
            |receipt_with_bloom| match receipt.tx_type() {
                SeismicTxType::Legacy => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
                SeismicTxType::Eip2930 => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
                SeismicTxType::Eip1559 => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
                SeismicTxType::Eip7702 => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
                SeismicTxType::Seismic => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            },
        )?;

        Ok(Self { base })
    }

    /// Builds [`SeismicTransactionReceipt`] by combing core (l1) receipt fields and additional OP
    /// receipt fields.
    pub fn build(self) -> SeismicTransactionReceipt {
        self.base
    }
}
