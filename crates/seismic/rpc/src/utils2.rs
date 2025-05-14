//! Utils for testing the seismic rpc api

use alloy_rpc_types::{BlockTransactions, TransactionRequest};
use reth_rpc_eth_api::{helpers::FullEthApi, RpcBlock};

/// Override the request for seismic calls
pub fn seismic_override_call_request(request: &mut TransactionRequest) {
    // If user calls with the standard (unsigned) eth_call,
    // then disregard whatever they put in the from field
    // They will still be able to read public contract functions,
    // but they will not be able to spoof msg.sender in these calls
    request.from = None;
    request.gas_price = None; // preventing InsufficientFunds error
    request.max_fee_per_gas = None; // preventing InsufficientFunds error
    request.max_priority_fee_per_gas = None; // preventing InsufficientFunds error
    request.max_fee_per_blob_gas = None; // preventing InsufficientFunds error
    request.value = None; // preventing InsufficientFunds error
}

/// Test utils for the seismic rpc api
/// copied from reth-rpc-api-builder
#[cfg(test)]
pub mod test_utils {
    use crate::SeismicEthApiBuilder;
    use alloy_rpc_types_engine::{ClientCode, ClientVersionV1};
    use jsonrpsee::Methods;
    use reth_chainspec::{ChainSpec, ChainSpec as SeismicChainSpec, MAINNET};
    use reth_consensus::noop::NoopConsensus;
    use reth_engine_primitives::BeaconConsensusEngineHandle;
    use reth_ethereum_engine_primitives::EthEngineTypes;
    use reth_evm::execute::BasicBlockExecutorProvider;
    use reth_network_api::noop::NoopNetwork;
    use reth_node_builder::rpc::EthApiBuilder;
    use reth_node_ethereum::EthereumEngineValidator;
    use reth_payload_builder::test_utils::spawn_test_payload_service;
    use reth_provider::{
        test_utils::{NoopProvider, TestCanonStateSubscriptions},
        BlockReader, BlockReaderIdExt, ChainSpecProvider, StateProviderFactory,
    };
    use reth_rpc::{eth, EthApi};
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
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use reth_seismic_evm::SeismicEvmConfig;
    use reth_seismic_primitives::{SeismicPrimitives, SeismicTransactionSigned};
    use reth_seismic_txpool::SeismicPooledTransaction;
    use reth_tasks::{pool::BlockingTaskPool, TokioTaskExecutor};
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore,
        noop::{MockTransactionValidator, NoopTransactionPool},
        test_utils::{testing_pool, MockOrdering, TestPool, TestPoolBuilder},
        CoinbaseTipOrdering, Pool,
    };
    use seismic_alloy_network::Seismic;
    use seismic_revm::SeismicTransaction;
    use std::{
        default,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };
    use tokio::sync::mpsc::unbounded_channel;
    use crate::{SeismicEthApi};

    /// Localhost with port 0 so a free port is used.
    pub const fn test_address() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }

    /// Launches a new server for the auth module
    pub async fn launch_auth(secret: JwtSecret) -> AuthServerHandle {
        let config = AuthServerConfig::builder(secret).socket_addr(test_address()).build();
        let (tx, _rx) = unbounded_channel();
        let beacon_engine_handle = BeaconConsensusEngineHandle::<EthEngineTypes>::new(tx);
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
            true, // idk if this is correct
        );
        let module = AuthRpcModule::new(engine_api);
        module.start_server(config).await.unwrap()
    }

    // /// Launches a new server with http only with the given modules
    // pub async fn launch_http(modules: impl Into<Methods>) -> RpcServerHandle {
    //     let builder = test_seismic_rpc_builder();
    //     let eth_api = builder.bootstrap_eth_api();
    //     // let seismic_eth_api = SeismicEthApi { inner: eth_api.inner.clone() };
    //     let mut server = builder.build(
    //         TransportRpcModuleConfig::set_http(RpcModuleSelection::Standard),
    //         *Box::new(eth_api),
    //     );
    //     server.replace_configured(modules).unwrap();
    //     RpcServerConfig::http(Default::default())
    //         .with_http_address(test_address())
    //         .start(&server)
    //         .await
    //         .unwrap()
    // }

    // type SeismicTestPool = Pool<
    //     MockTransactionValidator<SeismicPooledTransaction>,
    //     CoinbaseTipOrdering<SeismicPooledTransaction>,
    //     InMemoryBlobStore,
    // >;
    // /// Returns an [`RpcModuleBuilder`] with testing components.
    // pub fn test_seismic_rpc_builder() -> RpcModuleBuilder<
    //     SeismicPrimitives,
    //     NoopProvider<SeismicChainSpec, SeismicPrimitives>,
    //     SeismicTestPool,
    //     NoopNetwork,
    //     TokioTaskExecutor,
    //     SeismicEvmConfig,
    //     BasicBlockExecutorProvider<SeismicEvmConfig>,
    //     NoopConsensus,
    // > {
    //     let spec = SEISMIC_MAINNET.clone();

    //     let test_pool = Pool::new(
    //         MockTransactionValidator::default(),
    //         CoinbaseTipOrdering::<SeismicPooledTransaction>::default(),
    //         InMemoryBlobStore::default(),
    //         Default::default(),
    //     );

    //     RpcModuleBuilder::default()
    //         .with_provider(NoopProvider::<SeismicChainSpec, SeismicPrimitives>::new(spec.clone()))
    //         .with_pool(test_pool)
    //         .with_network(NoopNetwork::default())
    //         .with_executor(TokioTaskExecutor::default())
    //         .with_evm_config(SeismicEvmConfig::seismic(spec.clone()))
    //         .with_block_executor(BasicBlockExecutorProvider::new(SeismicEvmConfig::seismic(
    //             spec.clone(),
    //         )))
    //         .with_consensus(NoopConsensus::default())
    // }

    // /// Builds a test eth api
    // pub fn build_test_eth_api<
    //     P: BlockReaderIdExt<
    //             Block = reth_primitives::Block,
    //             Receipt = reth_primitives::Receipt,
    //             Header = reth_primitives::Header,
    //         > + BlockReader
    //         + ChainSpecProvider<ChainSpec = ChainSpec>
    //         + StateProviderFactory
    //         + Unpin
    //         + Clone
    //         + 'static,
    // >(
    //     provider: P,
    // ) -> EthApi<P, TestPool, NoopNetwork, SeismicEvmConfig> {
    //     let evm_config = SeismicEvmConfig::new(provider.chain_spec());
    //     let cache = EthStateCache::spawn(provider.clone(), Default::default());
    //     let fee_history_cache = FeeHistoryCache::new(FeeHistoryCacheConfig::default());

    //     EthApi::new(
    //         provider.clone(),
    //         testing_pool(),
    //         NoopNetwork::default(),
    //         cache.clone(),
    //         GasPriceOracle::new(provider, Default::default(), cache),
    //         GasCap::default(),
    //         DEFAULT_MAX_SIMULATE_BLOCKS,
    //         DEFAULT_ETH_PROOF_WINDOW,
    //         BlockingTaskPool::build().expect("failed to build tracing pool"),
    //         fee_history_cache,
    //         evm_config,
    //         DEFAULT_PROOF_PERMITS,
    //     )
    // }
}
