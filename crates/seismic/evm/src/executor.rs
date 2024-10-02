use reth_node_builder::{components::ExecutorBuilder, BuilderContext};
use reth_node_api::FullNodeTypes;
use reth_node_ethereum::EthExecutorProvider;

use crate::evm_config::SeismicEvmConfig;
/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for SeismicExecutorBuilder
where
    Node: FullNodeTypes,
{
    type EVM = SeismicEvmConfig;
    type Executor = EthExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        Ok((
            SeismicEvmConfig::default(),
            EthExecutorProvider::new(ctx.chain_spec(), SeismicEvmConfig::default()),
        ))
    }
}
