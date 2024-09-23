use derive_more::Deref;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{
    core::{JsonRawValue, RpcResult},
    types::{ErrorCode, ErrorObject},
};
use reth::core::rpc::eth::helpers::{
    AddDevSigners, Call, EthApiSpec, EthBlocks, EthCall, EthFees, EthSigner, EthState,
    EthTransactions, LoadBlock, LoadFee, LoadPendingBlock, LoadReceipt, LoadState, LoadTransaction,
    SpawnBlocking, Trace,
};
use reth::core::rpc::eth::EthApiTypes;
use secp256k1::SecretKey;

use crate::evm_config::SEISMIC_DB;
use crate::rpc::error::SeismicApiError;
use crate::rpc::transaction::SeismicTransactions;
use reth::rpc::server_types::eth::revm_utils::CallFees;
use reth::rpc::server_types::eth::EthApiBuilderCtx;
use reth::rpc::server_types::eth::PendingBlock;
use reth::rpc::server_types::eth::RpcInvalidTransactionError;
use reth::rpc::server_types::eth::{EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth::tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskExecutor, TaskSpawner,
};
use reth_evm::provider::EvmEnvProvider;
use reth_evm::ConfigureEvm;
use reth_network_api::NetworkInfo;
use reth_node_api::{BuilderProvider, FullNodeComponents};
use reth_node_core::rpc::eth::RawTransactionForwarder;
use reth_primitives::TxKind;
use reth_primitives::U256;
use reth_primitives::{
    revm_primitives::{BlockEnv, TxEnv},
    Address, B256,
};
use reth_provider::{
    BlockIdReader, BlockNumReader, BlockReaderIdExt, ChainSpecProvider, HeaderProvider,
    StageCheckpointReader, StateProviderFactory,
};
use reth_provider::{CanonStateSubscriptions, TransactionsProvider};
use reth_rpc::eth::{core::EthApiInner, DevSigner};
use reth_rpc_eth_api::{FromEthApiError, IntoEthApiError};
use reth_rpc_types::{TransactionRequest, WithOtherFields};
use reth_transaction_pool::TransactionPool;
use seismic_preimages::{Commitment, InputPreImage};
use std::{fmt, sync::Arc};
use tracing::trace;

use crate::helpers::signer::{AddCustomDevSigners, CustomDevSigner};

pub const TEST_BYTECODE_PATH: &str = "src/seismic_tx_test_bytecode.txt";

/// Adapter for [`EthApiBuilderCtx`].
// pub type EthApiBuilderCtx<N> = reth:``:rpc::server_types::eth::EthApiBuilderCtx<
//     <N as FullNodeTypes>::Provider,
//     <N as FullNodeComponents>::Pool,
//     <N as FullNodeComponents>::Evm,
//     <N as FullNodeComponents>::Network,
//     TaskExecutor,
//     // TaskExecutor, TODO: genericize this
//     <N as FullNodeTypes>::Provider,
// >;

#[cfg_attr(not(test), rpc(server, namespace = "seismic"))]
#[cfg_attr(test, rpc(server, client, namespace = "seismic"))]
pub trait SeismicApi {
    #[method(name = "commit")]
    fn seismic_commit(
        &self,
        address: Address,
        preimages: Vec<InputPreImage>,
    ) -> RpcResult<Vec<Commitment>>;

    /// Sends a transaction; will block waiting for signer to return the
    /// transaction hash. Handler detects a Seismic transaction with preimages
    /// in the im
    #[method(name = "sendTransaction")]
    async fn send_transaction(
        &self,
        request: WithOtherFields<TransactionRequest>,
    ) -> RpcResult<B256>;
}

// pub type EthApiNodeBackend = EthApiInner<
//
//     <N as FullNodeTypes>::Provider,
//     <N as FullNodeComponents>::Pool,
//     <N as FullNodeComponents>::Network,
//     <N as FullNodeComponents>::Evm,
// >;
//
#[derive(Clone, Deref)]
pub struct SeismicApi<Provider, Pool, Network, EvmConfig> {
    #[deref]
    inner: Arc<EthApiInner<Provider, Pool, Network, EvmConfig>>,
}

impl<Provider, Pool, Network, EvmConfig> SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    EvmConfig: Clone,
    Network: Clone,
{
    /// Creates a new instance for given context.
    #[allow(clippy::type_complexity)]
    pub fn with_spawner<Tasks, Events>(
        ctx: &EthApiBuilderCtx<Provider, Pool, EvmConfig, Network, Tasks, Events>,
    ) -> Self
    where
        Tasks: TaskSpawner + Clone + 'static,
        Events: CanonStateSubscriptions,
    {
        let blocking_task_pool =
            BlockingTaskPool::build().expect("failed to build blocking task pool");

        let inner = EthApiInner::new(
            ctx.provider.clone(),
            ctx.pool.clone(),
            ctx.network.clone(),
            ctx.cache.clone(),
            ctx.new_gas_price_oracle(),
            ctx.config.rpc_gas_cap,
            ctx.config.eth_proof_window,
            blocking_task_pool,
            ctx.new_fee_history_cache(),
            ctx.evm_config.clone(),
            ctx.executor.clone(),
            None,
            ctx.config.proof_permits,
        );

        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<Provider, Pool, Network, EvmConfig> EthApiTypes
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: Send + Sync,
{
    type Error = SeismicApiError;
}

impl<Provider, Pool, Network, EvmConfig> EthApiSpec
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Pool: TransactionPool + 'static,
    Provider: ChainSpecProvider + BlockNumReader + StageCheckpointReader + 'static,
    Network: NetworkInfo + 'static,
    EvmConfig: Send + Sync,
{
    fn provider(&self) -> impl ChainSpecProvider + BlockNumReader + StageCheckpointReader {
        self.inner.provider()
    }

    fn network(&self) -> impl NetworkInfo {
        self.inner.network()
    }

    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
    }

    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn reth_rpc_eth_api::helpers::EthSigner>>> {
        self.inner.signers()
    }
}

impl<Provider, Pool, Network, EvmConfig> SpawnBlocking
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: Send + Sync + Clone + 'static,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    #[inline]
    fn io_task_spawner(&self) -> impl TaskSpawner {
        self.inner.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.inner.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.inner.blocking_task_guard()
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadFee for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadBlock,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    #[inline]
    fn provider(&self) -> impl BlockIdReader + HeaderProvider + ChainSpecProvider {
        self.inner.provider()
    }

    #[inline]
    fn cache(&self) -> &EthStateCache {
        self.inner.cache()
    }

    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<impl BlockReaderIdExt> {
        self.inner.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache {
        self.inner.fee_history_cache()
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadState
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: Send + Sync,
    Provider: StateProviderFactory + ChainSpecProvider,
    Pool: TransactionPool,
{
    #[inline]
    fn provider(&self) -> impl StateProviderFactory + ChainSpecProvider {
        self.inner.provider()
    }

    #[inline]
    fn cache(&self) -> &EthStateCache {
        self.inner.cache()
    }

    #[inline]
    fn pool(&self) -> impl TransactionPool {
        self.inner.pool()
    }
}

impl<Provider, Pool, Network, EvmConfig> EthState for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadState + SpawnBlocking,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }
}

impl<Provider, Pool, Network, EvmConfig> EthFees for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadFee,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
}

impl<Provider, Pool, Network, EvmConfig> Trace for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadState,
    EvmConfig: ConfigureEvm,
{
    #[inline]
    fn evm_config(&self) -> &impl ConfigureEvm {
        self.inner.evm_config()
    }
}

impl<Provider, Pool, Network, EvmConfig> AddDevSigners
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    fn with_dev_accounts(&self) {
        *self.inner.signers().write() = DevSigner::random_signers(20);
    }
}

impl<Provider, Pool, Network, EvmConfig> AddCustomDevSigners
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    fn add_custom_dev_signers(&mut self, secret_keys: &[SecretKey], addresses: &[Address]) {
        *self.inner.signers().write() = CustomDevSigner::new(secret_keys, addresses);
    }
}

impl<Provider, Pool, Network, EvmConfig> fmt::Debug
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeismicApi").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<Provider, Pool, Network, EvmConfig> SeismicApiServer
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Pool: TransactionPool + 'static,
    Provider: ChainSpecProvider
        + BlockNumReader
        + StageCheckpointReader
        + BlockReaderIdExt
        + Clone
        + EvmEnvProvider
        + StateProviderFactory
        + 'static,
    Network: NetworkInfo + Clone + 'static,
    EvmConfig: Send + Sync + ConfigureEvm + Clone + 'static,
{
    fn seismic_commit(
        &self,
        address: Address,
        preimages: Vec<InputPreImage>,
    ) -> RpcResult<Vec<Commitment>> {
        let mut db = SEISMIC_DB.clone();
        match seismic_preimages::bulk_commit(&mut db, &address, &preimages) {
            Ok(commitments) => RpcResult::Ok(commitments),
            Err(e) => {
                let msg = e.message();
                let code = match e {
                    seismic_preimages::SeismicRpcError::ParseError(_) => ErrorCode::ParseError,
                    seismic_preimages::SeismicRpcError::DbError(_) => ErrorCode::InternalError,
                };
                RpcResult::Err(ErrorObject::owned(code.code(), msg, None::<&JsonRawValue>))
            }
        }
    }

    async fn send_transaction(
        &self,
        request: WithOtherFields<TransactionRequest>,
    ) -> RpcResult<B256> {
        trace!(target: "rpc::eth", ?request, "Serving seismic_sendTransaction");
        Ok(SeismicTransactions::send_transaction(self, request).await?)
    }
}

impl<Provider, Pool, Network, EvmConfig> SeismicTransactions
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadTransaction,
    Pool: TransactionPool + 'static,
    Provider: BlockReaderIdExt,
{
    fn provider(&self) -> impl BlockReaderIdExt {
        self.inner.provider()
    }

    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner>>> {
        self.inner.signers()
    }
}

impl<Provider, Pool, Network, EvmConfig> EthBlocks
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadBlock + EthApiSpec + LoadTransaction,
    Self::Error: From<SeismicApiError>,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    #[inline]
    fn provider(&self) -> impl HeaderProvider {
        self.inner.provider()
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadBlock
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadPendingBlock + SpawnBlocking,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    #[inline]
    fn provider(&self) -> impl BlockReaderIdExt {
        self.inner.provider()
    }

    #[inline]
    fn cache(&self) -> &EthStateCache {
        self.inner.cache()
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadPendingBlock
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: SpawnBlocking,
    Provider: BlockReaderIdExt + EvmEnvProvider + ChainSpecProvider + StateProviderFactory,
    Pool: TransactionPool,
    EvmConfig: ConfigureEvm,
{
    #[inline]
    fn provider(
        &self,
    ) -> impl BlockReaderIdExt + EvmEnvProvider + ChainSpecProvider + StateProviderFactory {
        self.inner.provider()
    }

    #[inline]
    fn pool(&self) -> impl TransactionPool {
        self.inner.pool()
    }

    #[inline]
    fn pending_block(&self) -> &tokio::sync::Mutex<Option<PendingBlock>> {
        self.inner.pending_block()
    }

    #[inline]
    fn evm_config(&self) -> &impl ConfigureEvm {
        self.inner.evm_config()
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadTransaction
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: SpawnBlocking,
    Provider: TransactionsProvider,
    Pool: TransactionPool,
{
    type Pool = Pool;

    fn provider(&self) -> impl TransactionsProvider {
        self.inner.provider()
    }

    fn cache(&self) -> &EthStateCache {
        self.inner.cache()
    }

    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }
}

impl<Provider, Pool, Network, EvmConfig> EthTransactions
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadTransaction,
    Provider: ChainSpecProvider + BlockReaderIdExt + Clone + 'static,
    Pool: Clone,
    Network: Clone,
    EvmConfig: Clone,
{
    fn provider(&self) -> impl BlockReaderIdExt {
        self.inner.provider()
    }

    fn raw_tx_forwarder(&self) -> Option<Arc<dyn RawTransactionForwarder>> {
        self.inner.raw_tx_forwarder()
    }

    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner>>> {
        self.inner.signers()
    }
}

impl<Provider, Pool, Network, EvmConfig> EthCall for SeismicApi<Provider, Pool, Network, EvmConfig> where
    Self: Call + LoadPendingBlock
{
}

impl<Provider, Pool, Network, EvmConfig> Call for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadState + SpawnBlocking,
    EvmConfig: ConfigureEvm,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn evm_config(&self) -> &impl ConfigureEvm {
        self.inner.evm_config()
    }

    fn create_txn_env(
        &self,
        block_env: &BlockEnv,
        request: TransactionRequest,
    ) -> Result<TxEnv, Self::Error> {
        // Ensure that if versioned hashes are set, they're not empty
        if request
            .blob_versioned_hashes
            .as_ref()
            .map_or(false, |hashes| hashes.is_empty())
        {
            return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into_eth_err());
        }

        let TransactionRequest {
            from,
            to,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas,
            value,
            input,
            nonce,
            access_list,
            chain_id,
            blob_versioned_hashes,
            max_fee_per_blob_gas,
            // authorization_list,
            ..
        } = request;

        let CallFees {
            max_priority_fee_per_gas,
            gas_price,
            max_fee_per_blob_gas,
        } = CallFees::ensure_fees(
            gas_price.map(U256::from),
            max_fee_per_gas.map(U256::from),
            max_priority_fee_per_gas.map(U256::from),
            block_env.basefee,
            blob_versioned_hashes.as_deref(),
            max_fee_per_blob_gas.map(U256::from),
            block_env.get_blob_gasprice().map(U256::from),
        )?;

        let gas_limit = gas.unwrap_or_else(|| block_env.gas_limit.min(U256::from(u64::MAX)).to());

        #[allow(clippy::needless_update)]
        let env = TxEnv {
            gas_limit: gas_limit
                .try_into()
                .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)
                .map_err(Self::Error::from_eth_err)?,
            nonce,
            caller: from.unwrap_or_default(),
            gas_price,
            gas_priority_fee: max_priority_fee_per_gas,
            transact_to: to.unwrap_or(TxKind::Create),
            value: value.unwrap_or_default(),
            data: input
                .try_into_unique_input()
                .map_err(Self::Error::from_eth_err)?
                .unwrap_or_default(),
            chain_id,
            access_list: access_list.unwrap_or_default().into(),
            // EIP-4844 fields
            blob_hashes: blob_versioned_hashes.unwrap_or_default(),
            max_fee_per_blob_gas,
            authorization_list: Default::default(),
            // Commented out Optimism-specific fields for Seismic
            // optimism: OptimismFields { enveloped_tx: Some(Bytes::new()), ..Default::default() },
        };

        Ok(env)
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadReceipt
    for SeismicApi<Provider, Pool, Network, EvmConfig>
where
    Self: Send + Sync,
{
    #[inline]
    fn cache(&self) -> &EthStateCache {
        self.inner.cache()
    }
}

impl<N, Network> BuilderProvider<N> for SeismicApi<N::Provider, N::Pool, Network, N::Evm>
where
    N: FullNodeComponents,
    Network: Send + Sync + Clone + 'static,
{
    type Ctx<'a> =
        &'a EthApiBuilderCtx<N::Provider, N::Pool, N::Evm, Network, TaskExecutor, N::Provider>;

    fn builder() -> Box<dyn for<'a> Fn(Self::Ctx<'a>) -> Self + Send> {
        Box::new(|ctx| Self::with_spawner(ctx))
    }
}


