use futures::Future;
use reth_primitives::{
    revm_primitives::{db::DatabaseRef, BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg},
    Bytes, U256,
};
use reth_revm::{database::StateProviderDatabase, db::CacheDB, primitives::ResultAndState};
use reth_rpc_eth_api::{
    helpers::{Call, LoadPendingBlock},
    FromEthApiError,
};
use reth_rpc_eth_types::{
    cache::db::{StateCacheDbRefMutWrapper, StateProviderTraitObjWrapper},
    error::ensure_success,
    revm_utils::cap_tx_gas_limit_with_caller_allowance,
    utils::recover_raw_transaction,
    EthApiError,
};
use reth_rpc_types::{BlockId, TransactionRequest};
use reth_rpc_types_compat::transaction::transaction_to_call_request;
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
            let transaction_request =
                transaction_to_call_request(recovered.into_ecrecovered_transaction());

            let (res, _env) = SeismicCall::transact_call_at(
                self,
                transaction_request,
                block_number.unwrap_or_default(),
            )
            .await?;

            ensure_success(res.result).map_err(Self::Error::from_eth_err)
        }
    }

    /// Executes the call request at the given [`BlockId`].
    fn transact_call_at(
        &self,
        request: TransactionRequest,
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
        request: TransactionRequest,
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
        request: TransactionRequest,
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

        let request_gas = request.gas;
        let mut env = self.build_call_evm_env(cfg, block, request)?;

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
}
