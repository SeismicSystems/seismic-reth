//! Loads and formats OP transaction RPC response.

use super::ext::SeismicTransaction;
use crate::{eth::SeismicNodeCore, utils::recover_typed_data_request, SeismicEthApi};
use alloy_consensus::{transaction::Recovered, Transaction as _};
use alloy_primitives::{Bytes, PrimitiveSignature as Signature, B256};
use alloy_rpc_types_eth::{Transaction, TransactionInfo};
use reth_node_api::FullNodeComponents;
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
use seismic_alloy_consensus::{Decodable712, SeismicTxEnvelope, TypedDataRequest};
use seismic_alloy_network::{Network, Seismic};
use seismic_alloy_rpc_types::SeismicTransactionRequest;

impl<N> EthTransactions for SeismicEthApi<N>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    N: SeismicNodeCore<Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>>,
{
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.inner.signers()
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    ///
    /// Returns the hash of the transaction.
    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        let recovered = recover_raw_transaction(&tx)?;

        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        // submit the transaction to the pool with a `Local` origin
        let hash = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        Ok(hash)
    }
}

impl<N> SeismicTransaction for SeismicEthApi<N>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    N: SeismicNodeCore<Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>>,
    <<<SeismicEthApi<N> as RpcNodeCore>::Pool as TransactionPool>::Transaction as PoolTransaction>::Pooled: Decodable712,
{
    async fn send_typed_data_transaction(&self, tx: TypedDataRequest) -> Result<B256, Self::Error> {
        let recovered = recover_typed_data_request(&tx)?;

        // broadcast raw transaction to subscribers if there is any.
        // TODO: maybe we need to broadcast the encoded tx instead of the recovered tx
        // when other nodes receive the raw bytes the hash they recover needs to be
        // type
        // self.broadcast_raw_transaction(recovered.to);

        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        // submit the transaction to the pool with a `Local` origin
        let hash = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        Ok(hash)
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
        _request: alloy_rpc_types_eth::TransactionRequest,
    ) -> Result<SeismicTransactionSigned, Self::Error> {
        let request = SeismicTransactionRequest {
            inner: _request,
            seismic_elements: None, /* Assumed that the transaction has already been decrypted in
                                     * the EthApiExt */
        };
        let Ok(tx) = request.build_typed_tx() else {
            return Err(EthApiError::TransactionConversionError)
        };

        // Create an empty signature for the transaction.
        let signature = Signature::new(Default::default(), Default::default(), false);
        Ok(SeismicTransactionSigned::new_unhashed(tx, signature))
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
