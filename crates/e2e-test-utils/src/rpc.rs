use alloy_consensus::TxEnvelope;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_network::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, B256};
use alloy_rpc_types_eth::Account;
use reth_chainspec::EthereumHardforks;
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_builder::{rpc::RpcRegistry, NodeTypes};
use reth_provider::BlockReader;
use reth_rpc_api::DebugApiServer;
use reth_rpc_eth_api::{
    helpers::{EthApiSpec, EthState, FullEthApi, TraceExt},
    EthApiTypes, RpcReceipt,
};

#[allow(missing_debug_implementations)]
pub struct RpcTestContext<Node: FullNodeComponents, EthApi: EthApiTypes> {
    pub inner: RpcRegistry<Node, EthApi>,
}

impl<Node, EthApi> RpcTestContext<Node, EthApi>
where
    Node: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthereumHardforks,
            Primitives: NodePrimitives<
                Block = reth_primitives::Block,
                Receipt = reth_primitives::Receipt,
            >,
        >,
    >,
    EthApi:
        EthApiSpec<Provider: BlockReader<Block = reth_primitives::Block>> + FullEthApi + TraceExt,
{
    /// Injects a raw transaction into the node tx pool via RPC server
    pub async fn inject_tx(&self, raw_tx: Bytes) -> Result<B256, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        eth_api.send_raw_transaction(raw_tx).await
    }

    /// Retrieves a transaction envelope by its hash
    pub async fn envelope_by_hash(&self, hash: B256) -> eyre::Result<TxEnvelope> {
        let tx = self.inner.debug_api().raw_transaction(hash).await?.unwrap();
        let tx = tx.to_vec();
        Ok(TxEnvelope::decode_2718(&mut tx.as_ref()).unwrap())
    }

    /// get transaction receipt
    pub async fn transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<RpcReceipt<EthApi::NetworkTypes>>, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        eth_api.transaction_receipt(tx_hash).await
    }

    /// get code
    pub async fn get_code(
        &self,
        address: Address,
        block_number: u64,
    ) -> Result<Bytes, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        EthState::get_code(
            eth_api,
            address,
            Some(BlockId::Number(BlockNumberOrTag::Number(block_number.into()))),
        )
        .await
    }

    pub async fn get_account(
        &self,
        address: Address,
        block_number: u64,
    ) -> Result<Option<Account>, EthApi::Error> {
        let eth_api = self.inner.eth_api();
        EthState::get_account(
            eth_api,
            address,
            BlockId::Number(BlockNumberOrTag::Number(block_number.into())),
        )
        .await
    }
}
