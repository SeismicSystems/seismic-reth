use futures::Future;
use reth_primitives::{
    revm_primitives::{db::DatabaseRef, BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg}, transaction::FillTxEnv, Bytes, PooledTransactionsElement, TransactionSigned, TransactionSignedEcRecovered, TxKind, U256
};
use reth_revm::{database::StateProviderDatabase, db::CacheDB, primitives::{AuthorizationList, ResultAndState, SignedAuthorization, TxEnv}};
use reth_rpc_eth_api::{
    helpers::{Call, LoadPendingBlock},
    FromEthApiError, IntoEthApiError,
};
use reth_rpc_eth_types::{
    cache::db::{StateCacheDbRefMutWrapper, StateProviderTraitObjWrapper},
    error::ensure_success,
    revm_utils::{cap_tx_gas_limit_with_caller_allowance, CallFees},
    utils::recover_raw_transaction,
    EthApiError, RpcInvalidTransactionError,
};
use reth_rpc_types::{BlockId, TransactionRequest};
use tracing::trace;

/// Seismic call related functions
pub trait SeismicCall: Call + LoadPendingBlock {
    /// Executes the call request (`eth_call`) and returns the output
    fn call(
        &self,
        request: Bytes,
        block_number: Option<BlockId>,
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + Send {
        async move {
            // `call` must be accompanied with a valid signature.
            let recovered = recover_raw_transaction(request.clone())?;
            // let tx = match recovered.into_transaction() {
            //     PooledTransactionsElement::Seismic { transaction, .. } => {
            //         transaction
            //     }
            //     _ => {
            //         return Err(RpcInvalidTransactionError::TxTypeNotSupported.into_eth_err());
            //     }
            // };
            let transaction = recovered.into_ecrecovered_transaction();

            let (res, _env) = SeismicCall::transact_call_at(
                self,
                transaction,
                block_number.unwrap_or_default(),
            )
            .await?;

            ensure_success(res.result).map_err(Self::Error::from_eth_err)
        }
    }

    /// Executes the call request at the given [`BlockId`].
    fn transact_call_at(
        &self,
        request: TransactionSignedEcRecovered,
        at: BlockId,
    ) -> impl Future<Output = Result<(ResultAndState, EnvWithHandlerCfg), Self::Error>> + Send
    where
        Self: LoadPendingBlock,
    {
        let this = self.clone();
        SeismicCall::spawn_with_call_at(self, request, at, move |db, env| this.transact(db, env))
    }

    /// Prepares the state and env for the given [`TransactionRequest`] at the given [`BlockId`] and
    /// executes the closure on a new task returning the result of the closure.
    ///
    /// This returns the configured [`EnvWithHandlerCfg`] for the given [`TransactionRequest`] at
    /// the given [`BlockId`] and with configured call settings: `prepare_call_env`.
    fn spawn_with_call_at<F, R>(
        &self,
        request: TransactionSignedEcRecovered,
        at: BlockId,
        f: F,
    ) -> impl Future<Output = Result<R, Self::Error>> + Send
    where
        Self: LoadPendingBlock,
        F: FnOnce(StateCacheDbRefMutWrapper<'_, '_>, EnvWithHandlerCfg) -> Result<R, Self::Error>
            + Send
            + 'static,
        R: Send + 'static,
    {
        async move {
            let (cfg, block_env, at) = self.evm_env_at(at).await?;
            let this = self.clone();
            self.spawn_tracing(move |_| {
                let state = this.state_at_block_id(at)?;
                let mut db =
                    CacheDB::new(StateProviderDatabase::new(StateProviderTraitObjWrapper(&state)));

                let env = SeismicCall::prepare_call_env(
                    &this,
                    cfg,
                    block_env,
                    request,
                    this.call_gas_limit(),
                    &mut db,
                )?;

                f(StateCacheDbRefMutWrapper(&mut db), env)
            })
            .await
        }
    }

    /// Overrides `EthCall::prepare_call_env` to enable static-only execution
    fn prepare_call_env<DB>(
        &self,
        mut cfg: CfgEnvWithHandlerCfg,
        block: BlockEnv,
        request: TransactionSignedEcRecovered,
        gas_limit: u64,
        db: &mut CacheDB<DB>,
    ) -> Result<EnvWithHandlerCfg, Self::Error>
    where
        DB: DatabaseRef,
        EthApiError: From<<DB as DatabaseRef>::Error>,
    {
        // we want to disable this in eth_call, since this is common practice used by other node
        // impls and providers <https://github.com/foundry-rs/foundry/issues/4388>
        cfg.disable_block_gas_limit = true;

        // Disabled because eth_call is sometimes used with eoa senders
        // See <https://github.com/paradigmxyz/reth/issues/1959>
        cfg.disable_eip3607 = true;

        // The basefee should be ignored for eth_call
        // See:
        // <https://github.com/ethereum/go-ethereum/blob/ee8e83fa5f6cb261dad2ed0a7bbcde4930c41e6c/internal/ethapi/api.go#L985>
        cfg.disable_base_fee = true;

        // Can only execute static functions, as to prevent viewing unauthorized state
        cfg.execute_static = true;

        // set nonce to None so that the correct nonce is chosen by the EVM
        // request.nonce = None;

        let request_gas = request.gas_limit();
        let mut env = SeismicCall::build_call_evm_env(self, cfg, block, request)?;

        if request_gas.is_none() {
            // No gas limit was provided in the request, so we need to cap the transaction gas limit
            if env.tx.gas_price > U256::ZERO {
                // If gas price is specified, cap transaction gas limit with caller allowance
                trace!(target: "rpc::eth::call", ?env, "Applying gas limit cap with caller allowance");
                cap_tx_gas_limit_with_caller_allowance(db, &mut env.tx)?;
            } else {
                // If no gas price is specified, use maximum allowed gas limit. The reason for this
                // is that both Erigon and Geth use pre-configured gas cap even if
                // it's possible to derive the gas limit from the block:
                // <https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/cmd/rpcdaemon/commands/trace_adhoc.go#L956
                // https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/eth/ethconfig/config.go#L94>
                trace!(target: "rpc::eth::call", ?env, "Applying gas limit cap as the maximum gas limit");
                env.tx.gas_limit = gas_limit;
            }
        }

        Ok(env)
    }

    /// Creates a new [`EnvWithHandlerCfg`] to be used for executing the [`TransactionRequest`] in
    /// `eth_call`.
    ///
    /// Note: this does _not_ access the Database to check the sender.
    fn build_call_evm_env(
        &self,
        cfg: CfgEnvWithHandlerCfg,
        block: BlockEnv,
        request: TransactionSignedEcRecovered,
    ) -> Result<EnvWithHandlerCfg, Self::Error> {
        let tx = SeismicCall::create_txn_env(self, &block, request)?;
        Ok(EnvWithHandlerCfg::new_with_cfg_env(cfg, block, tx))
    }

    /// Configures a new [`TxEnv`]  for the [`TransactionRequest`]
    ///
    /// All [`TxEnv`] fields are derived from the given [`TransactionRequest`], if fields are
    /// `None`, they fall back to the [`BlockEnv`]'s settings.
    fn create_txn_env(
        &self,
        block_env: &BlockEnv,
        request: TransactionSignedEcRecovered,
    ) -> Result<TxEnv, Self::Error> {
        // Ensure that if versioned hashes are set, they're not empty
        if request.transaction.blob_versioned_hashes().as_ref().map_or(false, |hashes| hashes.is_empty()) {
            return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into_eth_err())
        }

        let CallFees { max_priority_fee_per_gas, gas_price, max_fee_per_blob_gas } =
            CallFees::ensure_fees(
                Some(U256::from(request.transaction.gas_price())),
                Some(U256::from(request.transaction.max_fee_per_gas())),
                request.max_priority_fee_per_gas().map(U256::from),
                block_env.basefee,
                request.transaction.blob_versioned_hashes().as_deref(),
                request.transaction.max_fee_per_blob_gas().map(U256::from),
                block_env.get_blob_gasprice().map(U256::from),
            )?;

            let gas_limit = if request.transaction.gas_limit() == 0 {
                block_env.gas_limit.min(U256::from(u64::MAX)).to()
            } else {
                request.transaction.gas_limit()
            };

        #[allow(clippy::needless_update)]
        let env = TxEnv {
            gas_limit: gas_limit
                .try_into()
                .map_err(|_| RpcInvalidTransactionError::GasUintOverflow)
                .map_err(Self::Error::from_eth_err)?,
            nonce: Some(request.transaction.nonce()),
            caller: request.signer(),   // Caller must be the signer
            gas_price,
            gas_priority_fee: max_priority_fee_per_gas,
            transact_to: request.transaction.kind(),
            value: request.transaction.value(),
            data: *request.transaction.input(),
            chain_id: request.transaction.chain_id(),
            access_list: request.transaction.access_list().map_or(vec![], |access_list| access_list.clone().into()),
            // EIP-4844 fields
            blob_hashes: request.transaction.blob_versioned_hashes().unwrap_or_default(),
            max_fee_per_blob_gas,
            // EIP-7702 fields
            authorization_list: request.transaction.authorization_list().map(|list| *<&[SignedAuthorization] as Into<AuthorizationList>>::into(list.clone())),
            ..Default::default()
        };

        Ok(env)
    }
}
