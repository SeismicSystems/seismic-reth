#![allow(missing_docs)]

// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(feature = "seismic"))]
compile_error!("Cannot build the `seismic-reth` binary with the `seismic` feature flag disabled.");

#[cfg(feature = "seismic")]
fn main() {
    use eyre::Ok;
    use reth::{
        builder::NodeBuilder,
        cli::Cli,
        rpc::server_types::eth::{EthApiBuilderCtx, EthStateCache},
        tasks::TaskManager,
    };
    use reth_evm_seismic::evm_config::SeismicEvmConfig;
    use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
    use reth_provider::test_utils::TestCanonStateSubscriptions;
    use reth_tasks::TokioTaskExecutor;
    use reth_tracing::{RethTracer, Tracer};

    use reth_helpers_seismic::{chain::seismic_chain, signer::AddCustomDevSigners};
    use reth_node_seismic::node::{SeismicAddOns, SeismicNode};
    use reth_rpc_seismic::core::{SeismicApi, SeismicApiServer};

    use reth_primitives::Address;
    use secp256k1::SecretKey;
    use std::str::FromStr;

    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::parse_args().run(|builder, _| async move {
        let seismic_secret_key: SecretKey =
            SecretKey::from_str("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let seismic_address: Address =
            Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        let _guard = RethTracer::new().init()?;

        let tasks = TaskManager::current();
        let node_config = NodeConfig::test()
            .dev()
            .with_rpc(RpcServerArgs::default().with_http())
            .with_chain(seismic_chain());

        let node_builder = NodeBuilder::new(node_config)
            .testing_node(tasks.executor())
            .with_types::<SeismicNode>()
            .with_components(SeismicNode::components())
            .with_add_ons::<SeismicAddOns>()
            .extend_rpc_modules(move |ctx| {
                // can be made cleaner
                let provider = ctx.provider().clone();
                let pool = ctx.pool().clone();
                let network = ctx.network().clone();
                let cache = EthStateCache::spawn(
                    provider.clone(),
                    Default::default(),
                    SeismicEvmConfig::default().clone(),
                );
                let events = TestCanonStateSubscriptions::default();
                let seismic_ctx = EthApiBuilderCtx {
                    provider: provider.clone(),
                    pool: pool.clone(),
                    network: network.clone(),
                    cache: EthStateCache::spawn(
                        provider,
                        Default::default(),
                        SeismicEvmConfig::default().clone(),
                    ),
                    executor: TokioTaskExecutor::default(),
                    evm_config: SeismicEvmConfig::default(),
                    config: Default::default(),
                    events: TestCanonStateSubscriptions::default(),
                };
                let mut seismic_api = SeismicApi::with_spawner(&seismic_ctx);
                seismic_api.add_custom_dev_signers(&[seismic_secret_key], &[seismic_address]);
                let signers = seismic_api.signers().read().clone();
                // if signers.is_empty() {
                //     panic!("No signers found in SeismicApi");
                // }
                for signer in signers.iter() {
                    let x = signer.accounts();
                    println!("signer: {:?}", x);
                }
                ctx.modules.merge_configured(seismic_api.into_rpc())?;
                Ok(())
            });

        let handle = node_builder.launch().await.unwrap();

        println!("Launched Seismic node");
        handle.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
