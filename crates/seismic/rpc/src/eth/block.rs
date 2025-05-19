//! Loads and formats OP block RPC response.

use alloy_consensus::{transaction::TransactionMeta, BlockHeader};
use alloy_rpc_types_eth::BlockId;
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec};
use reth_node_api::BlockBody;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_eth_api::{
    helpers::{EthBlocks, LoadBlock, LoadPendingBlock, LoadReceipt, SpawnBlocking},
    types::RpcTypes,
    RpcNodeCore, RpcReceipt,
};
use reth_rpc_eth_types::EthApiError;
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use reth_storage_api::{BlockReader, HeaderProvider};
use seismic_alloy_rpc_types::SeismicTransactionReceipt;

use crate::{eth::SeismicNodeCore, SeismicEthApi};

use super::receipt::SeismicReceiptBuilder;

impl<N> EthBlocks for SeismicEthApi<N>
where
    Self: LoadBlock<
        Error = EthApiError,
        NetworkTypes: RpcTypes<Receipt = SeismicTransactionReceipt>,
        Provider: BlockReader<Receipt = SeismicReceipt, Transaction = SeismicTransactionSigned>,
    >,
    N: SeismicNodeCore<
        Provider: BlockReader + ChainSpecProvider<ChainSpec = ChainSpec> + HeaderProvider,
    >,
{
    async fn block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<RpcReceipt<Self::NetworkTypes>>>, Self::Error>
    where
        Self: LoadReceipt,
    {
        if let Some((block, receipts)) = self.load_block_and_receipts(block_id).await? {
            let block_number = block.number();
            let base_fee = block.base_fee_per_gas();
            let block_hash = block.hash();
            let excess_blob_gas = block.excess_blob_gas();
            let timestamp = block.timestamp();
            let blob_params = self.provider().chain_spec().blob_params_at_timestamp(timestamp);

            return block
                .body()
                .transactions()
                .iter()
                .zip(receipts.iter())
                .enumerate()
                .map(|(idx, (tx, receipt))| {
                    let meta = TransactionMeta {
                        tx_hash: *tx.tx_hash(),
                        index: idx as u64,
                        block_hash,
                        block_number,
                        base_fee,
                        excess_blob_gas,
                        timestamp,
                    };
                    SeismicReceiptBuilder::new(tx, meta, receipt, &receipts, blob_params)
                        .map(|builder| builder.build())
                })
                .collect::<Result<Vec<_>, Self::Error>>()
                .map(Some)
        }

        Ok(None)
    }
}

impl<N> LoadBlock for SeismicEthApi<N>
where
    Self: LoadPendingBlock + SpawnBlocking,
    N: SeismicNodeCore,
{
}
