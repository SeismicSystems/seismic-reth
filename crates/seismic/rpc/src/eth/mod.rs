//! Seismic-Reth `eth_` endpoint implementation.

pub mod ext;
pub mod receipt;
pub mod transaction;
pub mod utils;

pub use receipt::SeismicReceiptConverter;

mod block;
mod call;
mod pending_block;

use crate::{
    eth::transaction::{SeismicRpcTxConverter, SeismicSimTxConverter},
    SeismicEthApiError,
};
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_eips::BlockId;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_eth::AccountInfo;
use futures::Future;
use reth_evm::{ConfigureEvm, SpecFor, TxEnvFor};
use reth_node_api::{FullNodeComponents, HeaderTy};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_rpc::{
    eth::{core::EthApiInner, DevSigner},
    RpcTypes,
};
use reth_rpc_eth_api::{
    helpers::{
        pending_block::BuildPendingEnv, spec::SignersForApi, AddDevSigners, EthApiSpec, EthCall,
        EthFees, EthState, LoadFee, LoadPendingBlock, LoadState, SpawnBlocking, Trace,
    },
    EthApiTypes, FromEthApiError, FromEvmError, FullEthApiServer, RpcConvert, RpcConverter,
    RpcNodeCore, RpcNodeCoreExt, SignableTxRequest,
};
use reth_rpc_eth_types::{EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth_rpc_layer::Whitelist;
use reth_storage_api::{BlockReader, ProviderHeader, ProviderTx};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskSpawner,
};
use seismic_alloy_network::SeismicReth;
use seismic_revm::SeismicTransaction;
use std::{fmt, marker::PhantomData, sync::Arc};

use reth_rpc_convert::transaction::{EthTxEnvError, TryIntoTxEnv};
use revm_context::{BlockEnv, CfgEnv, TxEnv};
use seismic_alloy_rpc_types::SeismicTransactionRequest;

// Additional imports for SignableTxRequest wrapper
use alloy_primitives::Signature;
use reth_rpc_convert::SignTxRequestError;
use seismic_alloy_network::TxSigner;

/// Newtype wrapper around `SeismicTransactionRequest` to implement `SignableTxRequest`
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SignableSeismicTransactionRequest(pub SeismicTransactionRequest);

// Requests can contain decrypted calldata, so `Debug` is intentionally redacted.
impl fmt::Debug for SignableSeismicTransactionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignableSeismicTransactionRequest")
            .field("transaction_type", &self.0.inner.transaction_type)
            .field("has_seismic_elements", &self.0.seismic_elements.is_some())
            .field("request", &"<redacted>")
            .finish()
    }
}

impl From<SeismicTransactionRequest> for SignableSeismicTransactionRequest {
    fn from(req: SeismicTransactionRequest) -> Self {
        Self(req)
    }
}

impl From<alloy_rpc_types_eth::TransactionRequest> for SignableSeismicTransactionRequest {
    fn from(req: alloy_rpc_types_eth::TransactionRequest) -> Self {
        Self(SeismicTransactionRequest { inner: req, seismic_elements: None })
    }
}

impl AsRef<alloy_rpc_types_eth::TransactionRequest> for SignableSeismicTransactionRequest {
    fn as_ref(&self) -> &alloy_rpc_types_eth::TransactionRequest {
        &self.0.inner
    }
}

impl AsMut<alloy_rpc_types_eth::TransactionRequest> for SignableSeismicTransactionRequest {
    fn as_mut(&mut self) -> &mut alloy_rpc_types_eth::TransactionRequest {
        &mut self.0.inner
    }
}

impl TryIntoTxEnv<seismic_revm::SeismicTransaction<TxEnv>> for SignableSeismicTransactionRequest {
    type Err = EthTxEnvError;

    fn try_into_tx_env<Spec>(
        self,
        cfg_env: &CfgEnv<Spec>,
        block_env: &BlockEnv,
    ) -> Result<seismic_revm::SeismicTransaction<TxEnv>, Self::Err> {
        // First convert the inner transaction to TxEnv
        let base_tx_env = self.0.inner.try_into_tx_env(cfg_env, block_env)?;
        // Then wrap it in SeismicTransaction
        Ok(seismic_revm::SeismicTransaction::new(base_tx_env))
    }
}

impl SignableTxRequest<reth_seismic_primitives::SeismicTransactionSigned>
    for SignableSeismicTransactionRequest
{
    /// Node-side signing (`eth_sendTransaction`/`eth_signTransaction`) is unsupported on Seismic:
    /// it would have the node custody keys and build a transaction from a plaintext request, which
    /// does not fit Seismic's client-side-encryption model. Reject rather than return a fabricated
    /// placeholder transaction.
    async fn try_build_and_sign(
        self,
        _signer: impl TxSigner<Signature> + Send,
    ) -> Result<reth_seismic_primitives::SeismicTransactionSigned, SignTxRequestError> {
        Err(SignTxRequestError::InvalidTransactionRequest)
    }
}

/// Wrapper network type that uses `SignableSeismicTransactionRequest`
#[derive(Debug, Clone)]
pub struct SeismicRethWithSignable;

impl reth_rpc_eth_api::RpcTypes for SeismicRethWithSignable {
    type TransactionRequest = SignableSeismicTransactionRequest;
    type Receipt = <SeismicReth as reth_rpc_eth_api::RpcTypes>::Receipt;
    type TransactionResponse = <SeismicReth as reth_rpc_eth_api::RpcTypes>::TransactionResponse;
    type Header = <SeismicReth as reth_rpc_eth_api::RpcTypes>::Header;
}

/// Adapter for [`EthApiInner`], which holds all the data required to serve core `eth_` API.
pub type EthApiNodeBackend<N, Rpc> = EthApiInner<N, Rpc>;

/// A helper trait with requirements for [`RpcNodeCore`] to be used in [`SeismicEthApi`].
pub trait SeismicNodeCore: RpcNodeCore<Provider: BlockReader> {}
impl<T> SeismicNodeCore for T where T: RpcNodeCore<Provider: BlockReader> {}

/// seismic-reth `Eth` API implementation.
#[derive(Clone)]
pub struct SeismicEthApi<N: SeismicNodeCore, Rpc: RpcConvert> {
    /// Inner `Eth` API implementation.
    pub inner: Arc<EthApiInner<N, Rpc>>,
    /// Shared ops whitelist used to intercept sentinel transactions.
    pub ops_whitelist: Option<Whitelist>,
}

impl<N: RpcNodeCore, Rpc: RpcConvert> SeismicEthApi<N, Rpc> {
    /// Returns a reference to the [`EthApiNodeBackend`].
    pub fn eth_api(&self) -> &EthApiNodeBackend<N, Rpc> {
        &self.inner
    }

    /// Build a [`SeismicEthApi`] using [`SeismicEthApiBuilder`].
    pub const fn builder() -> SeismicEthApiBuilder<Rpc> {
        SeismicEthApiBuilder::new()
    }
}

impl<N, Rpc> EthApiTypes for SeismicEthApi<N, Rpc>
where
    // Self: Send + Sync,
    // N: SeismicNodeCore,
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    type Error = SeismicEthApiError;
    type NetworkTypes = Rpc::Network;
    type RpcConvert = Rpc;

    fn tx_resp_builder(&self) -> &Self::RpcConvert {
        self.inner.tx_resp_builder()
    }
}

impl<N, Rpc> RpcNodeCore for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    type Primitives = N::Primitives;
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Evm = N::Evm;
    type Network = N::Network;

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.inner.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.inner.network()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.inner.provider()
    }
}

impl<N, Rpc> RpcNodeCoreExt for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    #[inline]
    fn cache(&self) -> &EthStateCache<N::Primitives> {
        self.inner.cache()
    }
}

impl<N, Rpc> EthApiSpec for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    type Transaction = ProviderTx<Self::Provider>;
    type Rpc = Rpc::Network;

    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
    }

    #[inline]
    fn signers(&self) -> &SignersForApi<Self> {
        self.inner.signers()
    }
}

impl<N, Rpc> SpawnBlocking for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
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

impl<N, Rpc> LoadFee for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.inner.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache<ProviderHeader<N::Provider>> {
        self.inner.fee_history_cache()
    }
}

impl<N, Rpc> LoadState for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
    Self: LoadPendingBlock,
{
}

impl<N, Rpc> EthState for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    TxEnvFor<N::Evm>: From<SeismicTransaction<TxEnv>>,
    SeismicTransaction<TxEnv>: Into<TxEnvFor<N::Evm>>,
    Rpc: RpcConvert<
        Primitives = N::Primitives,
        Error = SeismicEthApiError,
        TxEnv = TxEnvFor<N::Evm>,
        Spec = SpecFor<N::Evm>,
    >,
    <<Self as EthApiTypes>::NetworkTypes as reth_rpc_eth_api::RpcTypes>::TransactionRequest:
        From<alloy_rpc_types_eth::TransactionRequest>,
    Self: LoadPendingBlock + EthCall,
{
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }

    #[inline]
    fn storage_apis_enabled(&self) -> bool {
        self.inner.storage_apis_enabled()
    }

    /// Returns the native balance for `address` — the standard `eth_getBalance` behavior,
    /// consistent with `eth_getAccount`/`eth_getProof`. The USDC-backed effective balance
    /// (`max(native, usdc·10^12)`) is available opt-in via the `includeGasToken` parameter on
    /// the `eth_getBalance` override (see `ext.rs`).
    fn balance(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> impl Future<Output = Result<U256, Self::Error>> + Send {
        self.spawn_blocking_io_fut(move |this| async move {
            let state = this.state_at_block_id_or_latest(block_id).await?;
            Ok(state
                .account_balance(&address)
                .map_err(Self::Error::from_eth_err)?
                .unwrap_or_default())
        })
    }

    /// Reports the raw native balance for `eth_getAccountInfo`, matching [`Self::balance`] and
    /// the other account-surface endpoints (`eth_getAccount`/`eth_getProof`).
    ///
    /// All account-inspection RPCs return the same native balance by default, so consumers never
    /// see a different value for the same account at the same block (Veridise 1206). The
    /// USDC-backed effective balance (`max(native, usdc·10^12)`) is opt-in via the
    /// `includeGasToken` parameter on the `eth_getBalance` and `eth_getAccountInfo` overrides
    /// (see `ext.rs`); the gas-allowance execution path (`estimateGas`/`call`) keeps accounting
    /// for USDC independently.
    fn get_account_info(
        &self,
        address: Address,
        block_id: BlockId,
    ) -> impl Future<Output = Result<AccountInfo, Self::Error>> + Send {
        self.spawn_blocking_io_fut(move |this| async move {
            let state = this.state_at_block_id(block_id).await?;
            let account = state
                .basic_account(&address)
                .map_err(Self::Error::from_eth_err)?
                .unwrap_or_default();

            let balance = account.balance;
            let nonce = account.nonce;
            let code = if account.get_bytecode_hash() == KECCAK_EMPTY {
                Default::default()
            } else {
                state
                    .account_code(&address)
                    .map_err(Self::Error::from_eth_err)?
                    .unwrap_or_default()
                    .original_bytes()
            };

            Ok(AccountInfo { balance, nonce, code })
        })
    }
}

impl<N, Rpc> EthFees for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
}

impl<N, Rpc> Trace for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
}

impl<N, Rpc> AddDevSigners for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<
        Network: RpcTypes<TransactionRequest: SignableTxRequest<ProviderTx<N::Provider>>>,
    >,
{
    fn with_dev_accounts(&self) {
        *self.inner.signers().write() = DevSigner::random_signers(20)
    }
}

impl<N: SeismicNodeCore, Rpc: RpcConvert> fmt::Debug for SeismicEthApi<N, Rpc> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeismicEthApi").finish_non_exhaustive()
    }
}

/// Converter for Seismic RPC types.
pub type SeismicRpcConvert<N, NetworkT> = RpcConverter<
    NetworkT,
    <N as FullNodeComponents>::Evm,
    SeismicReceiptConverter,
    (),
    (),
    crate::eth::transaction::SeismicSimTxConverter,
    crate::eth::transaction::SeismicRpcTxConverter,
>;

/// Builds [`SeismicEthApi`] for Optimism.
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
    N: FullNodeComponents<
        Evm: ConfigureEvm<
            NextBlockEnvCtx: BuildPendingEnv<HeaderTy<N::Types>>
                                 // + From<ExecutionPayloadBaseV1>
                                 + Unpin,
        >,
    >,
    NetworkT: RpcTypes,
    SeismicRpcConvert<N, NetworkT>: RpcConvert<Network = NetworkT>,
    SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>:
        FullEthApiServer<Provider = N::Provider, Pool = N::Pool> + AddDevSigners,
{
    type EthApi = SeismicEthApi<N, SeismicRpcConvert<N, NetworkT>>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let ops_whitelist = ctx.ops_whitelist.clone();
        let receipt_converter = SeismicReceiptConverter::new();

        let rpc_converter: SeismicRpcConvert<N, NetworkT> = RpcConverter::new(receipt_converter)
            .with_sim_tx_converter(SeismicSimTxConverter::new())
            .with_rpc_tx_converter(SeismicRpcTxConverter::new());

        let eth_api = ctx.eth_api_builder().with_rpc_converter(rpc_converter).build_inner();

        Ok(SeismicEthApi { inner: Arc::new(eth_api), ops_whitelist })
    }
}

#[cfg(test)]
mod tests {
    use super::SignableSeismicTransactionRequest;
    use alloy_primitives::Bytes;
    use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
    use alloy_signer_local::PrivateKeySigner;
    use reth_rpc_convert::SignTxRequestError;
    use reth_rpc_eth_api::SignableTxRequest;

    #[test]
    fn debug_redacts_transaction_request_input() {
        const PRIVATE_INPUT: &[u8] = b"private-signable-request-input";

        let request = TransactionRequest {
            input: TransactionInput { input: Some(Bytes::from_static(PRIVATE_INPUT)), data: None },
            ..Default::default()
        };
        let request = SignableSeismicTransactionRequest::from(request);
        let debug = format!("{request:?}");
        let marker = alloy_primitives::hex::encode(PRIVATE_INPUT);

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&marker), "private request input leaked: {debug}");
    }

    /// Seismic rejects node-side signing rather than returning a fabricated placeholder tx
    /// (Veridise 1204), so `eth_sendTransaction`/`eth_signTransaction` fail cleanly.
    #[tokio::test]
    async fn try_build_and_sign_is_rejected() {
        let req = SignableSeismicTransactionRequest::from(
            alloy_rpc_types_eth::TransactionRequest::default(),
        );
        let result = req.try_build_and_sign(&PrivateKeySigner::random()).await;
        assert!(matches!(result, Err(SignTxRequestError::InvalidTransactionRequest)));
    }
}
