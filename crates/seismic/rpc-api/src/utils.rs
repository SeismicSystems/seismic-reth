//! Utils for testing the seismic rpc api

use alloy_primitives::{Address, TxKind, U256};
use alloy_rpc_types::TransactionRequest;

/// Test utils for the seismic rpc api
/// copied from reth-rpc-api-builder
#[cfg(test)]
pub mod test_utils {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };

    use alloy_rpc_types_engine::{ClientCode, ClientVersionV1};
    use jsonrpsee::Methods;
    use reth_beacon_consensus::BeaconConsensusEngineHandle;
    use reth_chainspec::{ChainSpec, MAINNET};
    use reth_consensus::noop::NoopConsensus;
    use reth_ethereum_engine_primitives::{EthEngineTypes, EthereumEngineValidator};
    use reth_evm::execute::BasicBlockExecutorProvider;
    use reth_evm_ethereum::{execute::EthExecutionStrategyFactory, EthEvmConfig};
    use reth_network_api::noop::NoopNetwork;
    use reth_payload_builder::test_utils::spawn_test_payload_service;
    use reth_provider::{
        test_utils::{NoopProvider, TestCanonStateSubscriptions},
        BlockReader, BlockReaderIdExt, ChainSpecProvider, EvmEnvProvider, StateProviderFactory,
    };
    use reth_rpc::EthApi;
    use reth_rpc_builder::{
        auth::{AuthRpcModule, AuthServerConfig, AuthServerHandle},
        RpcModuleBuilder, RpcServerConfig, RpcServerHandle, TransportRpcModuleConfig,
    };
    use reth_rpc_engine_api::{capabilities::EngineCapabilities, EngineApi};
    use reth_rpc_eth_types::{
        EthStateCache, FeeHistoryCache, FeeHistoryCacheConfig, GasCap, GasPriceOracle,
    };
    use reth_rpc_layer::JwtSecret;
    use reth_rpc_server_types::{
        constants::{DEFAULT_ETH_PROOF_WINDOW, DEFAULT_MAX_SIMULATE_BLOCKS, DEFAULT_PROOF_PERMITS},
        RpcModuleSelection,
    };
    use reth_tasks::{pool::BlockingTaskPool, TokioTaskExecutor};
    use reth_transaction_pool::{
        noop::NoopTransactionPool,
        test_utils::{testing_pool, TestPool, TestPoolBuilder},
    };
    use tokio::sync::mpsc::unbounded_channel;

    /// Localhost with port 0 so a free port is used.
    pub const fn test_address() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }

    /// Launches a new server for the auth module
    pub async fn launch_auth(secret: JwtSecret) -> AuthServerHandle {
        let config = AuthServerConfig::builder(secret).socket_addr(test_address()).build();
        let (tx, _rx) = unbounded_channel();
        let beacon_engine_handle =
            BeaconConsensusEngineHandle::<EthEngineTypes>::new(tx, Default::default());
        let client = ClientVersionV1 {
            code: ClientCode::RH,
            name: "Reth".to_string(),
            version: "v0.2.0-beta.5".to_string(),
            commit: "defa64b2".to_string(),
        };

        let engine_api = EngineApi::new(
            NoopProvider::default(),
            MAINNET.clone(),
            beacon_engine_handle,
            spawn_test_payload_service().into(),
            NoopTransactionPool::default(),
            Box::<TokioTaskExecutor>::default(),
            client,
            EngineCapabilities::default(),
            EthereumEngineValidator::new(MAINNET.clone()),
        );
        let module = AuthRpcModule::new(engine_api);
        module.start_server(config).await.unwrap()
    }

    /// Launches a new server with http only with the given modules
    pub async fn launch_http(modules: impl Into<Methods>) -> RpcServerHandle {
        let builder = test_rpc_builder();
        let mut server = builder.build(
            TransportRpcModuleConfig::set_http(RpcModuleSelection::Standard),
            Box::new(EthApi::with_spawner),
            Arc::new(EthereumEngineValidator::new(MAINNET.clone())),
        );
        server.merge_configured(modules).unwrap();
        RpcServerConfig::http(Default::default())
            .with_http_address(test_address())
            .start(&server)
            .await
            .unwrap()
    }

    /// Returns an [`RpcModuleBuilder`] with testing components.
    pub fn test_rpc_builder() -> RpcModuleBuilder<
        NoopProvider,
        TestPool,
        NoopNetwork,
        TokioTaskExecutor,
        TestCanonStateSubscriptions,
        EthEvmConfig,
        BasicBlockExecutorProvider<EthExecutionStrategyFactory>,
        NoopConsensus,
    > {
        RpcModuleBuilder::default()
            .with_provider(NoopProvider::default())
            .with_pool(TestPoolBuilder::default().into())
            .with_network(NoopNetwork::default())
            .with_executor(TokioTaskExecutor::default())
            .with_events(TestCanonStateSubscriptions::default())
            .with_evm_config(EthEvmConfig::new(MAINNET.clone()))
            .with_block_executor(BasicBlockExecutorProvider::new(
                EthExecutionStrategyFactory::mainnet(),
            ))
            .with_consensus(NoopConsensus::default())
    }

    /// Builds a test eth api
    pub fn build_test_eth_api<
        P: BlockReaderIdExt<
                Block = reth_primitives::Block,
                Receipt = reth_primitives::Receipt,
                Header = reth_primitives::Header,
            > + BlockReader
            + ChainSpecProvider<ChainSpec = ChainSpec>
            + EvmEnvProvider
            + StateProviderFactory
            + Unpin
            + Clone
            + 'static,
    >(
        provider: P,
    ) -> EthApi<P, TestPool, NoopNetwork, EthEvmConfig> {
        let evm_config = EthEvmConfig::new(provider.chain_spec());
        let cache = EthStateCache::spawn(provider.clone(), Default::default());
        let fee_history_cache = FeeHistoryCache::new(FeeHistoryCacheConfig::default());

        EthApi::new(
            provider.clone(),
            testing_pool(),
            NoopNetwork::default(),
            cache.clone(),
            GasPriceOracle::new(provider, Default::default(), cache),
            GasCap::default(),
            DEFAULT_MAX_SIMULATE_BLOCKS,
            DEFAULT_ETH_PROOF_WINDOW,
            BlockingTaskPool::build().expect("failed to build tracing pool"),
            fee_history_cache,
            evm_config,
            DEFAULT_PROOF_PERMITS,
        )
    }
}
