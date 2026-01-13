//! Seismic Eth API builder implementation.

use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeComponents, HeaderTy};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_provider::providers::NodeTypesForProvider;
use reth_rpc::RpcTypes;
use reth_rpc_eth_api::{helpers::AddDevSigners, FullEthApiServer, RpcConvert, RpcConverter};
use reth_seismic_primitives::SeismicPrimitives;
use reth_seismic_rpc::{
    SeismicEthApi, SeismicReceiptConverter, SeismicRpcConvert,
    SeismicRpcTxConverter, SeismicSimTxConverter,
};
use std::{marker::PhantomData, sync::Arc};

/// Builds [`SeismicEthApi`].
#[derive(Debug)]
pub struct SeismicEthApiBuilder<NetworkT> {
    _nt: PhantomData<NetworkT>,
}

impl<NetworkT> Default for SeismicEthApiBuilder<NetworkT> {
    fn default() -> Self {
        Self { _nt: PhantomData }
    }
}

impl<NetworkT> SeismicEthApiBuilder<NetworkT> {
    /// Creates a [`SeismicEthApiBuilder`] instance from core components.
    pub const fn new() -> Self {
        Self { _nt: PhantomData }
    }
}

impl<N, NetworkT> EthApiBuilder<N> for SeismicEthApiBuilder<NetworkT>
where
    N: FullNodeComponents<Evm: ConfigureEvm<
            NextBlockEnvCtx: reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<HeaderTy<N::Types>>
                                 + Unpin,
        >>,
    N::Types: NodeTypesForProvider<Primitives = SeismicPrimitives>,
    NetworkT: RpcTypes,
    SeismicRpcConvert<N, NetworkT>: RpcConvert<Network = NetworkT>,
    SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>:
        FullEthApiServer<Provider = N::Provider, Pool = N::Pool> + AddDevSigners,
{
    type EthApi = SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let receipt_converter = SeismicReceiptConverter::new();

        let rpc_converter: SeismicRpcConvert<N, NetworkT> = RpcConverter::new(receipt_converter)
            .with_sim_tx_converter(SeismicSimTxConverter::new())
            .with_rpc_tx_converter(SeismicRpcTxConverter::new());

        let eth_api = ctx.eth_api_builder().with_rpc_converter(rpc_converter).build_inner();

        Ok(SeismicEthApi { inner: Arc::new(eth_api) })
    }
}
