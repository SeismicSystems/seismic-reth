//! Seismic Node types config.
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_node_api::{FullNodeComponents, NodeAddOns};
use reth_node_builder::{
    components::ComponentsBuilder,
    node::{FullNodeTypes, NodeTypes},
    Node, PayloadTypes,
};
use reth_node_ethereum::{
    node::{
        EthereumConsensusBuilder, EthereumNetworkBuilder, EthereumPayloadBuilder,
        EthereumPoolBuilder,
    },
    EthEngineTypes,
};

use reth_chainspec::ChainSpec;
use reth_evm_seismic::{evm_config::SeismicEvmConfig, executor::SeismicExecutorBuilder};
use reth_rpc_seismic::core::SeismicApi;

/// Type configuration for a regular Seismic node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicNode;

impl SeismicNode {
    /// Creates a new instance of the Seismic node type.
    pub const fn new() -> Self {
        Self
    }

    /// Returns the components for the given [`RollupArgs`].
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        EthereumPayloadBuilder<SeismicEvmConfig>,
        EthereumNetworkBuilder,
        SeismicExecutorBuilder,
        EthereumConsensusBuilder,
    >
    where
        Node: FullNodeTypes,
        <Node as NodeTypes>::Engine: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default()) // TODO: change this to SeismicPoolBuilder
            .payload(EthereumPayloadBuilder::new(SeismicEvmConfig::default())) // TODO: change this to SeismicPayloadBuilde
            .network(EthereumNetworkBuilder::default()) // TODO: change this to SeismicNetworkBuilder
            .executor(SeismicExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default()) // TODO: change this to
                                                            // SeismicConsensusBuilder
    }
}

/// Add-ons w.r.t. Seismic
#[derive(Debug, Clone)]
pub struct SeismicAddOns;

impl<N: FullNodeComponents> NodeAddOns<N> for SeismicAddOns {
    type EthApi = SeismicApi<N::Provider, N::Pool, N::Network, SeismicEvmConfig>;
}

impl NodeTypes for SeismicNode {
    type Primitives = ();
    type Engine = EthEngineTypes;
    type ChainSpec = ChainSpec;
}

impl<N> Node<N> for SeismicNode
where
    N: FullNodeTypes<Engine = EthEngineTypes>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        EthereumPayloadBuilder<SeismicEvmConfig>,
        EthereumNetworkBuilder,
        SeismicExecutorBuilder,
        EthereumConsensusBuilder,
    >;

    type AddOns = SeismicAddOns;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }
}
