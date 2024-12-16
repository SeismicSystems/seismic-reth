use alloy_consensus::TxEnvelope;
use alloy_network::{eip2718::Decodable2718, Network};
use reth::{
    builder::{rpc::RpcRegistry, FullNodeComponents},
    rpc::api::{
        eth::helpers::{EthApiSpec, EthTransactions, FullEthApi, TraceExt},
        DebugApiServer,
    },
};
use reth_node_builder::EthApiTypes;
use reth_primitives::{Address, Bytes, B256};
use reth_rpc_types::{AnyTransactionReceipt, BlockId, BlockNumberOrTag, WithOtherFields};

#[allow(missing_debug_implementations)]
pub struct RpcTestContext<Node: FullNodeComponents, EthApi: EthApiTypes> {
    pub inner: RpcRegistry<Node, EthApi>,
}

impl<Node, EthApi> RpcTestContext<Node, EthApi>
where
    Node: FullNodeComponents,
    EthApi: EthApiSpec
        + FullEthApi<
            NetworkTypes: Network<
                TransactionResponse = WithOtherFields<alloy_rpc_types::Transaction>,
            >,
        > + TraceExt,
{
    /// Injects a raw transaction into the node tx pool via RPC server
    pub async fn inject_tx(&self, raw_tx: Bytes) -> Result<B256, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        eth_api.send_raw_transaction(raw_tx).await
    }

    /// call eth_call rpc endpoint
    pub async fn signed_call(
        &self,
        raw_tx: Bytes,
        block_number: u64,
    ) -> Result<Bytes, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        let block_id = Some(BlockId::Number(BlockNumberOrTag::Number(block_number.into())));
        eth_api.signed_call(raw_tx, block_id).await
    }

    /// call eth_getCode rpc endpoint
    pub async fn get_code(
        &self,
        address: Address,
        block_number: u64,
    ) -> Result<Bytes, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        let block_id = Some(BlockId::Number(BlockNumberOrTag::Number(block_number.into())));
        eth_api.get_code(address, block_id).await
    }

    /// get transaction receipt
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<AnyTransactionReceipt>, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        eth_api.transaction_receipt(tx_hash).await
    }

    /// Retrieves a transaction envelope by its hash
    pub async fn envelope_by_hash(&self, hash: B256) -> eyre::Result<TxEnvelope> {
        let tx = self.inner.debug_api().raw_transaction(hash).await?.unwrap();
        let tx = tx.to_vec();
        Ok(TxEnvelope::decode_2718(&mut tx.as_ref()).unwrap())
    }
}
