//! Loads and formats OP transaction RPC response.

use alloy_consensus::{transaction::Recovered, Transaction as _};
use alloy_primitives::{Bytes, PrimitiveSignature as Signature, Sealable, Sealed, B256};
use alloy_rpc_types_eth::TransactionInfo;
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
use seismic_alloy_rpc_types::SeismicTransactionRequest;

use crate::{eth::SeismicNodeCore, SeismicEthApi};

impl<N> EthTransactions for SeismicEthApi<N>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    N: SeismicNodeCore<Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>>,
    EthApi<N::Provider, N::Pool, N::Network, N::Evm>: EthTransactions,
{
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.0.signers()
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    ///
    /// Returns the hash of the transaction.
    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        self.0.send_raw_transaction(tx).await
    }
}

impl<N> LoadTransaction for SeismicEthApi<N>
where
    Self: SpawnBlocking + FullEthApiTypes + RpcNodeCoreExt,
    N: SeismicNodeCore<Provider: TransactionsProvider, Pool: TransactionPool>,
    Self::Pool: TransactionPool,
{
}

// impl<N> SeismicEthApi<N>
// where
//     N: SeismicNodeCore,
// {
//     /// Returns the [`SequencerClient`] if one is set.
//     pub fn raw_tx_forwarder(&self) -> Option<SequencerClient> {
//         self.inner.sequencer_client.clone()
//     }
// }

// impl<N> TransactionCompat<SeismicTransactionSigned> for SeismicEthApi<N>
// where
//     N: FullNodeComponents<Provider: ReceiptProvider<Receipt = SeismicReceipt>>,
// {
//     type Transaction = Transaction;
//     type Error = EthApiError;

//     fn fill(
//         &self,
//         tx: Recovered<SeismicTransactionSigned>,
//         tx_info: TransactionInfo,
//     ) -> Result<Self::Transaction, Self::Error> {
//         let tx = tx.convert::<SeismicTxEnvelope>();
//         let mut deposit_receipt_version = None;
//         let mut deposit_nonce = None;

//         if tx.is_deposit() {
//             // for depost tx we need to fetch the receipt
//             self.inner
//                 .eth_api
//                 .provider()
//                 .receipt_by_hash(tx.tx_hash())
//                 .map_err(Self::Error::from_eth_err)?
//                 .inspect(|receipt| {
//                     if let SeismicReceipt::Deposit(receipt) = receipt {
//                         deposit_receipt_version = receipt.deposit_receipt_version;
//                         deposit_nonce = receipt.deposit_nonce;
//                     }
//                 });
//         }

//         let TransactionInfo {
//             block_hash, block_number, index: transaction_index, base_fee, ..
//         } = tx_info;

//         let effective_gas_price = if tx.is_deposit() {
//             // For deposits, we must always set the `gasPrice` field to 0 in rpc
//             // deposit tx don't have a gas price field, but serde of `Transaction` will take care
// of             // it
//             0
//         } else {
//             base_fee
//                 .map(|base_fee| {
//                     tx.effective_tip_per_gas(base_fee).unwrap_or_default() + base_fee as u128
//                 })
//                 .unwrap_or_else(|| tx.max_fee_per_gas())
//         };

//         Ok(Transaction {
//             inner: alloy_rpc_types_eth::Transaction {
//                 inner: tx,
//                 block_hash,
//                 block_number,
//                 transaction_index,
//                 effective_gas_price: Some(effective_gas_price),
//             },
//             deposit_nonce,
//             deposit_receipt_version,
//         })
//     }

//     fn build_simulate_v1_transaction(
//         &self,
//         request: alloy_rpc_types_eth::TransactionRequest,
//     ) -> Result<SeismicTransactionSigned, Self::Error> {
//         let request: SeismicTransactionRequest = request.into();
//         let Ok(tx) = request.build_typed_tx() else {
//             return Err(EthApiError::Eth(EthApiError::TransactionConversionError))
//         };

//         // Create an empty signature for the transaction.
//         let signature = Signature::new(Default::default(), Default::default(), false);
//         Ok(SeismicTransactionSigned::new_unhashed(tx, signature))
//     }

//     fn otterscan_api_truncate_input(tx: &mut Self::Transaction) {
//         let input = match tx.inner.inner.inner_mut() {
//             SeismicTxEnvelope::Eip1559(tx) => &mut tx.tx_mut().input,
//             SeismicTxEnvelope::Eip2930(tx) => &mut tx.tx_mut().input,
//             SeismicTxEnvelope::Legacy(tx) => &mut tx.tx_mut().input,
//             SeismicTxEnvelope::Eip7702(tx) => &mut tx.tx_mut().input,
//             SeismicTxEnvelope::Deposit(tx) => {
//                 let (mut deposit, hash) = std::mem::replace(
//                     tx,
//                     Sealed::new_unchecked(Default::default(), Default::default()),
//                 )
//                 .split();
//                 deposit.input = deposit.input.slice(..4);
//                 let mut deposit = deposit.seal_unchecked(hash);
//                 std::mem::swap(tx, &mut deposit);
//                 return
//             }
//         };
//         *input = input.slice(..4);
//     }
// }
