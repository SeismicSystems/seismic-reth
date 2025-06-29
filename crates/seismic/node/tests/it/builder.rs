//! Node builder setup tests.

use reth_db::test_utils::create_test_rw_db;
use reth_node_api::{FullNodeComponents, NodeTypesWithDBAdapter};
use reth_node_builder::{Node, NodeBuilder, NodeConfig};
use reth_provider::providers::BlockchainProvider;
use reth_seismic_chainspec::SEISMIC_MAINNET;
use reth_seismic_node::node::SeismicNode;

#[test]
fn test_basic_setup() {
    // parse CLI -> config
    let config = NodeConfig::new(SEISMIC_MAINNET.clone());
    let db = create_test_rw_db();
    let seismic_node = SeismicNode::default();
    let _builder = NodeBuilder::new(config)
        .with_database(db)
        .with_types_and_provider::<SeismicNode, BlockchainProvider<NodeTypesWithDBAdapter<SeismicNode, _>>>()
        .with_components(seismic_node.components())
        .with_add_ons(seismic_node.add_ons())
        .on_component_initialized(move |ctx| {
            let _provider = ctx.provider();
            Ok(())
        })
        .on_node_started(|_full_node| Ok(()))
        .on_rpc_started(|_ctx, handles| {
            let _client = handles.rpc.http_client();
            Ok(())
        })
        .extend_rpc_modules(|ctx| {
            let _ = ctx.config();
            let _ = ctx.node().provider();

            Ok(())
        })
        .check_launch();
}
