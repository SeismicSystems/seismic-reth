use crate::{SeismicEthApi, SeismicEthApiError};
use alloy_consensus::transaction::Either;
use alloy_eips::eip7702::{RecoveredAuthorization, SignedAuthorization};
use alloy_primitives::{TxKind, U256};
use alloy_rpc_types_eth::transaction::TransactionRequest;
use reth_evm::{EvmEnv, EvmEnvFor, SpecFor, TxEnvFor};
use reth_rpc_eth_api::{
    helpers::{estimate::EstimateCall, Call, EthCall},
    CallFees, EthTxEnvError, FromEthApiError, FromEvmError, IntoEthApiError, RpcConvert,
    RpcNodeCore, RpcTxReq,
};
use reth_rpc_eth_types::{EthApiError, RpcInvalidTransactionError};
use reth_seismic_txpool::usdc::{
    gas_allowance, usdc_balance_storage_key, USDC_CONTRACT, USDC_DECIMAL_SCALE,
};
use revm::{
    context::TxEnv,
    context_interface::{Block, Transaction},
    Database,
};
use seismic_alloy_consensus::SeismicTxType;
use seismic_revm::{self, SeismicTransaction};

impl<N, Rpc> EthCall for SeismicEthApi<N, Rpc>
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
{
}

impl<N, Rpc> EstimateCall for SeismicEthApi<N, Rpc>
where
    Self: Call,
    Self::Error: From<EthApiError>,
    N: RpcNodeCore,
    Rpc: RpcConvert<
        Primitives = N::Primitives,
        Error = SeismicEthApiError,
        TxEnv = TxEnvFor<N::Evm>,
        Spec = SpecFor<N::Evm>,
    >,
{
}

impl<N, Rpc> Call for SeismicEthApi<N, Rpc>
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
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    /// Override the upstream allowance computation: on Seismic, gas can be paid
    /// in native token or USDC, while the transferred value always comes out of
    /// the native balance. Without this, `eth_estimateGas` rejects USDC-only
    /// wallets with `gas required exceeds allowance (0)`.
    ///
    /// Delegates to [`gas_allowance`], which mirrors the component-wise
    /// affordability rule the txpool enforces at admission via
    /// [`reth_seismic_txpool::usdc::can_afford`] (distinct from the single-scalar
    /// `native + usdc` bound the pool uses internally for promote/demote) — this
    /// only differs in reading balances from a [`Database`] instead of a
    /// [`StateProvider`](reth_provider::StateProvider).
    fn caller_gas_allowance(
        &self,
        mut db: impl Database<Error: Into<EthApiError>>,
        _evm_env: &EvmEnvFor<Self::Evm>,
        tx_env: &TxEnvFor<Self::Evm>,
    ) -> Result<u64, Self::Error> {
        let caller = tx_env.caller();
        let native = db
            .basic(caller)
            .map_err(|e| Self::Error::from_eth_err(e.into()))?
            .map(|acc| acc.balance)
            .unwrap_or_default();
        let storage_key = U256::from_be_bytes(usdc_balance_storage_key(&caller).0);
        let usdc = db
            .storage(USDC_CONTRACT, storage_key)
            .map_err(|e| Self::Error::from_eth_err(e.into()))?
            .value
            .saturating_mul(USDC_DECIMAL_SCALE);

        Ok(gas_allowance(native, usdc, tx_env.value(), U256::from(tx_env.gas_price()))
            .saturating_to())
    }

    fn create_txn_env(
        &self,
        evm_env: &EvmEnv<SpecFor<Self::Evm>>,
        request: RpcTxReq<Rpc::Network>,
        mut db: impl Database<Error: Into<EthApiError>>,
    ) -> Result<TxEnvFor<N::Evm>, Self::Error> {
        // Convert network request to concrete TransactionRequest
        let request: &TransactionRequest = request.as_ref();

        // Ensure that if versioned hashes are set, they're not empty
        if request.blob_versioned_hashes.as_ref().is_some_and(|hashes| hashes.is_empty()) {
            return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into_eth_err());
        }

        let tx_type = if request.authorization_list.is_some() {
            SeismicTxType::Eip7702
        } else if request.max_fee_per_gas.is_some() || request.max_priority_fee_per_gas.is_some() {
            SeismicTxType::Eip1559
        } else if request.access_list.is_some() {
            SeismicTxType::Eip2930
        } else {
            SeismicTxType::Seismic
        } as u8;

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
            authorization_list,
            transaction_type: _,
            sidecar: _,
        } = request;

        let CallFees { max_priority_fee_per_gas, gas_price, max_fee_per_blob_gas } =
            CallFees::ensure_fees(
                gas_price.map(U256::from),
                max_fee_per_gas.map(U256::from),
                max_priority_fee_per_gas.map(U256::from),
                U256::from(evm_env.block_env.basefee),
                blob_versioned_hashes.as_deref(),
                max_fee_per_blob_gas.map(U256::from),
                evm_env.block_env.blob_gasprice().map(U256::from),
            )
            .map_err(EthTxEnvError::CallFees)?;

        let gas_limit = gas.unwrap_or(
            // Use maximum allowed gas limit. The reason for this
            // is that both Erigon and Geth use pre-configured gas cap even if
            // it's possible to derive the gas limit from the block:
            // <https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/cmd/rpcdaemon/commands/trace_adhoc.go#L956
            // https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/eth/ethconfig/config.go#L94>
            evm_env.block_env.gas_limit,
        );

        let chain_id = chain_id.unwrap_or(evm_env.cfg_env.chain_id);

        let caller = from.unwrap_or_default();

        let nonce = if let Some(nonce) = nonce {
            *nonce
        } else {
            db.basic(caller).map_err(Into::into)?.map(|acc| acc.nonce).unwrap_or_default()
        };

        let authorization_list: Vec<Either<SignedAuthorization, RecoveredAuthorization>> =
            authorization_list
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|auth| Either::Left(auth.clone()))
                .collect();
        let env = TxEnv {
            tx_type,
            gas_limit,
            nonce,
            caller,
            gas_price: gas_price.saturating_to(),
            gas_priority_fee: max_priority_fee_per_gas.map(|v| v.saturating_to()),
            kind: to.unwrap_or(TxKind::Create),
            value: value.unwrap_or_default(),
            data: input
                .clone()
                .try_into_unique_input()
                .map_err(Self::Error::from_eth_err)?
                .unwrap_or_default(),
            chain_id: Some(chain_id),
            access_list: access_list.clone().unwrap_or_default(),
            // EIP-4844 fields
            blob_hashes: blob_versioned_hashes.clone().unwrap_or_default(),
            max_fee_per_blob_gas: max_fee_per_blob_gas
                .map(|v| v.saturating_to())
                .unwrap_or_default(),
            // EIP-7702 fields
            authorization_list,
        };

        tracing::debug!(
            target: "reth-seismic-rpc::eth::call",
            tx_type = env.tx_type(),
            gas_limit = env.gas_limit(),
            "created transaction environment"
        );

        Ok(SeismicTransaction { base: env, tx_hash: Default::default(), decryption_failed: false }
            .into())
    }
}
