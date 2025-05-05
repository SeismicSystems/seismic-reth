//! Payload component configuration for the Ethereum node.

use reth_chainspec::ChainSpec;
use reth_seismic_payload_builder::SeismicBuilderConfig;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypesWithEngine, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::PayloadBuilderBuilder, BuilderContext, PayloadBuilderConfig, PayloadTypes,
};
use reth_seismic_evm::SeismicEvmConfig;
use reth_seismic_primitives::{SeismicBlock, SeismicPrimitives};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use crate::engine::SeismicEngineTypes;
use reth_seismic_txpool::SeismicPooledTx;

/// A basic ethereum payload service.
#[derive(Clone, Default, Debug)]
#[non_exhaustive]
pub struct SeismicPayloadBuilder;

impl SeismicPayloadBuilder {
    /// A helper method initializing [`reth_ethereum_payload_builder::EthereumPayloadBuilder`] with
    /// the given EVM config.
    pub fn build<Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider, Evm>>
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<
                Payload = SeismicEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SeismicPrimitives,
            >,
        >,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        Evm: ConfigureEvm<Primitives = PrimitivesTy<Node::Types>>,
        // Txs: SeismicPayloadTransactions<Pool::Transaction>,
    {
        let conf = ctx.payload_builder_config();
        Ok(reth_seismic_payload_builder::SeismicPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            SeismicBuilderConfig::new().with_gas_limit(conf.gas_limit()),
        ))
    }
}

impl<Node, Pool> PayloadBuilderBuilder<Node, Pool> for SeismicPayloadBuilder
where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<
                Payload = SeismicEngineTypes,
                ChainSpec = ChainSpec,
                Primitives = SeismicPrimitives,
            >,
        >,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
            + Unpin
            + 'static,
        // Txs: SeismicPayloadTransactions<Pool::Transaction>,
        <Pool as TransactionPool>::Transaction: SeismicPooledTx,
{
    type PayloadBuilder =
        reth_seismic_payload_builder::SeismicPayloadBuilder<Pool, Node::Provider, SeismicEvmConfig>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::PayloadBuilder> {
        self.build(SeismicEvmConfig::seismic(ctx.chain_spec()), ctx, pool)
    }
}
