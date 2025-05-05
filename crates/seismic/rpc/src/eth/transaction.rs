//! Loads and formats OP transaction RPC response.

use alloy_consensus::{transaction::Recovered, Transaction as _};
use alloy_primitives::{Bytes, PrimitiveSignature as Signature, Sealable, Sealed, B256};
use alloy_rpc_types_eth::{Transaction, TransactionInfo};
use reqwest::Error;
use reth_node_api::FullNodeComponents;
use reth_rpc::EthApi;
use reth_rpc_eth_api::{
    helpers::{EthSigner, EthTransactions, LoadTransaction, SpawnBlocking},
    FromEthApiError, FullEthApiTypes, RpcNodeCore, RpcNodeCoreExt, TransactionCompat,
};
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError};
use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
use reth_storage_api::{
    BlockReader, BlockReaderIdExt, ProviderTx, ReceiptProvider, TransactionsProvider,
};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use seismic_alloy_consensus::SeismicTxEnvelope;
use seismic_alloy_network::{Network, Seismic};
use seismic_alloy_rpc_types::SeismicTransactionRequest;

use crate::{eth::SeismicNodeCore, SeismicEthApi};

impl<N> EthTransactions for SeismicEthApi<N>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    N: SeismicNodeCore<Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>>,
{
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.inner.eth_api.signers()
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    ///
    /// Returns the hash of the transaction.
    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        todo!() // seimsic specific stuff here?
    }
}

impl<N> LoadTransaction for SeismicEthApi<N>
where
    Self: SpawnBlocking + FullEthApiTypes + RpcNodeCoreExt,
    N: SeismicNodeCore<Provider: TransactionsProvider, Pool: TransactionPool>,
    Self::Pool: TransactionPool,
{
}

impl<N> TransactionCompat<SeismicTransactionSigned> for SeismicEthApi<N>
where
    N: FullNodeComponents<Provider: ReceiptProvider<Receipt = SeismicReceipt>>,
{
    type Transaction = <Seismic as Network>::TransactionResponse;
    type Error = EthApiError;

    fn fill(
        &self,
        tx: Recovered<SeismicTransactionSigned>,
        tx_info: TransactionInfo,
    ) -> Result<Self::Transaction, Self::Error> {
        let tx = tx.convert::<SeismicTxEnvelope>();

        let TransactionInfo {
            block_hash, block_number, index: transaction_index, base_fee, ..
        } = tx_info;

        let effective_gas_price = base_fee
            .map(|base_fee| {
                tx.effective_tip_per_gas(base_fee).unwrap_or_default() + base_fee as u128
            })
            .unwrap_or_else(|| tx.max_fee_per_gas());

        Ok(Transaction::<SeismicTxEnvelope> {
            inner: tx,
            block_hash,
            block_number,
            transaction_index,
            effective_gas_price: Some(effective_gas_price),
        })
    }

    fn build_simulate_v1_transaction(
        &self,
        request: alloy_rpc_types_eth::TransactionRequest,
    ) -> Result<SeismicTransactionSigned, Self::Error> {
        // let request: SeismicTransactionRequest = request.into();
        // let Ok(tx) = request.build_typed_tx() else {
        //     return Err(EthApiError::TransactionConversionError)
        // };

        // // Create an empty signature for the transaction.
        // let signature = Signature::new(Default::default(), Default::default(), false);
        // Ok(SeismicTransactionSigned::new_unhashed(tx, signature))
        todo!()
    }

    fn otterscan_api_truncate_input(tx: &mut Self::Transaction) {
        let input = match tx.inner.inner_mut() {
            SeismicTxEnvelope::Eip1559(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Eip2930(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Legacy(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Eip7702(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Seismic(tx) => &mut tx.tx_mut().input,
        };
        *input = input.slice(..4);
    }
}
