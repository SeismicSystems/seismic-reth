//! Loads and formats Seismic transaction RPC response.

use super::ext::SeismicTransaction;
use crate::{eth::SeismicNodeCore, utils::recover_typed_data_request, SeismicEthApi};
use alloy_consensus::{transaction::Recovered, Transaction as _};
use alloy_primitives::{Bytes, Signature, B256};
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
        tracing::debug!(target: "reth-seismic-rpc::eth", ?recovered, "serving seismic_eth_api::send_raw_transaction");

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
            SeismicTxEnvelope::Legacy(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Eip1559(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Eip2930(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Eip4844(tx) => &mut tx.tx_mut().input().clone(),
            SeismicTxEnvelope::Eip7702(tx) => &mut tx.tx_mut().input,
            SeismicTxEnvelope::Seismic(tx) => &mut tx.tx_mut().input,
        };
        *input = input.slice(..4);
    }
}

#[cfg(test)]
mod test {
    use alloy_primitives::{Bytes, FixedBytes};
    use reth_primitives_traits::SignedTransaction;
    use reth_rpc_eth_types::utils::recover_raw_transaction;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use std::str::FromStr;

    #[test]
    fn test_recover_raw_tx() {
        let raw_tx = Bytes::from_str("0x4af8d18214043083057e4083029605943ab946eec2553114040de82d2e18798a51cf1e1487038d7ea4c68000a1028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a08c7da3a99bf0f90d56551d99ea02b44e69e56c3bb999b8c98772ebb32aebcbd43b33e9e65a46333dfe6636f37f3009e93bad334235aec73bd54d11410e64eb2cab4da880a0e93185920818650416b4b0cc953c48f59fd9a29af4b7e1c4b1ac4824392f9220a079b76b064a83d423997b7234c575588f60da5d3e1e0561eff9804eb04c23789a").unwrap();
        let recovered = recover_raw_transaction::<SeismicTransactionSigned>(&raw_tx).unwrap();
        let expected = FixedBytes::<32>::from_str(
            "d578c4f5e787b2994749e68e44860692480ace52b219bbc0119919561cbc29ea",
        )
        .unwrap();
        assert_eq!(recovered.tx_hash(), &expected);
    }
}
