use super::SeismicNodeCore;
use crate::SeismicEthApi;
use alloy_consensus::transaction::Either;
use alloy_eips::eip7702::{RecoveredAuthorization, SignedAuthorization};
use alloy_primitives::{TxKind, U256};
use alloy_rpc_types_eth::transaction::TransactionRequest;
use reth_evm::{execute::BlockExecutorFactory, ConfigureEvm, EvmEnv, EvmFactory, SpecFor};
use reth_node_api::NodePrimitives;
use reth_rpc_eth_api::{
    helpers::{estimate::EstimateCall, Call, EthCall, LoadBlock, LoadState, SpawnBlocking},
    FromEthApiError, FromEvmError, FullEthApiTypes, IntoEthApiError,
};
use reth_rpc_eth_types::{revm_utils::CallFees, EthApiError, RpcInvalidTransactionError};
use reth_storage_api::{ProviderHeader, ProviderTx};
use revm::{context::TxEnv, context_interface::Block, Database};
use seismic_alloy_consensus::SeismicTxType;
use seismic_revm::{transaction::abstraction::RngMode, SeismicTransaction};
use tracing::debug;
use reth_rpc_eth_api::{AsEthApiError};
use alloy_rpc_types_eth::{state::StateOverride,};
use reth_chainspec::MIN_TRANSACTION_GAS;
use reth_evm::{EvmEnvFor, TransactionEnv};
use reth_revm::{database::StateProviderDatabase, db::CacheDB};
use reth_rpc_eth_types::{
    error::api::FromEvmHalt,
    revm_utils::{apply_state_overrides},
    RevertError
};
use reth_rpc_server_types::constants::gas_oracle::{CALL_STIPEND_GAS, ESTIMATE_GAS_ERROR_RATIO};
use reth_storage_api::StateProvider;
use revm::context_interface::{result::ExecutionResult, Transaction};
use tracing::trace;
use reth_rpc_eth_api::helpers::estimate::update_estimated_gas_range;
use reth_rpc_eth_types::EthResult;


impl<N> EthCall for SeismicEthApi<N>
where
    Self: EstimateCall + LoadBlock + FullEthApiTypes,
    N: SeismicNodeCore,
{
}

impl<N> EstimateCall for SeismicEthApi<N>
where
    Self: Call,
    Self::Error: From<EthApiError>,
    N: SeismicNodeCore,
{

    // Modified version of EstimateCall's default implimentation to use for SRC20 gas
    fn estimate_gas_with<S>(
        &self,
        mut evm_env: EvmEnvFor<Self::Evm>,
        mut request: TransactionRequest,
        state: S,
        state_override: Option<StateOverride>,
    ) -> Result<U256, Self::Error>
    where
        S: StateProvider,
    {
        println!("SeismicEthApi::estimate_gas_with");
        // Disabled because eth_estimateGas is sometimes used with eoa senders
        // See <https://github.com/paradigmxyz/reth/issues/1959>
        evm_env.cfg_env.disable_eip3607 = true;

        // The basefee should be ignored for eth_estimateGas and similar
        // See:
        // <https://github.com/ethereum/go-ethereum/blob/ee8e83fa5f6cb261dad2ed0a7bbcde4930c41e6c/internal/ethapi/api.go#L985>
        evm_env.cfg_env.disable_base_fee = true;

        // set nonce to None so that the correct nonce is chosen by the EVM
        request.nonce = None;

        // Keep a copy of gas related request values
        let tx_request_gas_limit = request.gas;
        let tx_request_gas_price = request.gas_price;
        // the gas limit of the corresponding block
        let block_env_gas_limit = evm_env.block_env.gas_limit;

        // Determine the highest possible gas limit, considering both the request's specified limit
        // and the block's limit.
        let mut highest_gas_limit = tx_request_gas_limit
            .map(|mut tx_gas_limit| {
                if block_env_gas_limit < tx_gas_limit {
                    // requested gas limit is higher than the allowed gas limit, capping
                    tx_gas_limit = block_env_gas_limit;
                }
                tx_gas_limit
            })
            .unwrap_or(block_env_gas_limit);

        // Configure the evm env
        let mut db = CacheDB::new(StateProviderDatabase::new(state));
        let mut tx_env = self.create_txn_env(&evm_env, request, &mut db)?;

        // Apply any state overrides if specified.
        if let Some(state_override) = state_override {
            apply_state_overrides(state_override, &mut db).map_err(Self::Error::from_eth_err)?;
        }

        // Optimize for simple transfer transactions, potentially reducing the gas estimate.
        if tx_env.input().is_empty() {
            if let TxKind::Call(to) = tx_env.kind() {
                if let Ok(code) = db.db.account_code(&to) {
                    let no_code_callee = code.map(|code| code.is_empty()).unwrap_or(true);
                    if no_code_callee {
                        // If the tx is a simple transfer (call to an account with no code) we can
                        // shortcircuit. But simply returning
                        // `MIN_TRANSACTION_GAS` is dangerous because there might be additional
                        // field combos that bump the price up, so we try executing the function
                        // with the minimum gas limit to make sure.
                        let mut tx_env = tx_env.clone();
                        tx_env.set_gas_limit(MIN_TRANSACTION_GAS);
                        if let Ok((res, _)) = self.transact(&mut db, evm_env.clone(), tx_env) {
                            if res.result.is_success() {
                                return Ok(U256::from(MIN_TRANSACTION_GAS))
                            }
                        }
                    }
                }
            }
        }

        // Check funds of the sender (only useful to check if transaction gas price is more than 0).
        //
        // The caller allowance is check by doing `(account.balance - tx.value) / tx.gas_price`
        if tx_env.gas_price() > 0 {
            // cap the highest gas limit by max gas caller can afford with given gas price
            highest_gas_limit = highest_gas_limit
                .min(seismic_caller_gas_allowance(&mut db, &tx_env).map_err(Self::Error::from_eth_err)?);
        }

        // If the provided gas limit is less than computed cap, use that
        tx_env.set_gas_limit(tx_env.gas_limit().min(highest_gas_limit));

        trace!(target: "rpc::eth::estimate", ?evm_env, ?tx_env, "Starting gas estimation");

        // Execute the transaction with the highest possible gas limit.
        let (mut res, (mut evm_env, mut tx_env)) =
            match self.transact(&mut db, evm_env.clone(), tx_env.clone()) {
                // Handle the exceptional case where the transaction initialization uses too much
                // gas. If the gas price or gas limit was specified in the request,
                // retry the transaction with the block's gas limit to determine if
                // the failure was due to insufficient gas.
                Err(err)
                    if err.is_gas_too_high() &&
                        (tx_request_gas_limit.is_some() || tx_request_gas_price.is_some()) =>
                {
                    return Err(self.map_out_of_gas_err(
                        block_env_gas_limit,
                        evm_env,
                        tx_env,
                        &mut db,
                    ))
                }
                Err(err) if err.is_gas_too_low() => {
                    // This failed because the configured gas cost of the tx was lower than what
                    // actually consumed by the tx This can happen if the
                    // request provided fee values manually and the resulting gas cost exceeds the
                    // sender's allowance, so we return the appropriate error here
                    return Err(RpcInvalidTransactionError::GasRequiredExceedsAllowance {
                        gas_limit: tx_env.gas_limit(),
                    }
                    .into_eth_err())
                }
                // Propagate other results (successful or other errors).
                ethres => ethres?,
            };

        let gas_refund = match res.result {
            ExecutionResult::Success { gas_refunded, .. } => gas_refunded,
            ExecutionResult::Halt { reason, .. } => {
                // here we don't check for invalid opcode because already executed with highest gas
                // limit
                return Err(Self::Error::from_evm_halt(reason, tx_env.gas_limit()))
            }
            ExecutionResult::Revert { output, .. } => {
                // if price or limit was included in the request then we can execute the request
                // again with the block's gas limit to check if revert is gas related or not
                return if tx_request_gas_limit.is_some() || tx_request_gas_price.is_some() {
                    Err(self.map_out_of_gas_err(block_env_gas_limit, evm_env, tx_env, &mut db))
                } else {
                    // the transaction did revert
                    Err(RpcInvalidTransactionError::Revert(RevertError::new(output)).into_eth_err())
                }
            }
        };

        // At this point we know the call succeeded but want to find the _best_ (lowest) gas the
        // transaction succeeds with. We find this by doing a binary search over the possible range.

        // we know the tx succeeded with the configured gas limit, so we can use that as the
        // highest, in case we applied a gas cap due to caller allowance above
        highest_gas_limit = tx_env.gas_limit();

        // NOTE: this is the gas the transaction used, which is less than the
        // transaction requires to succeed.
        let mut gas_used = res.result.gas_used();
        // the lowest value is capped by the gas used by the unconstrained transaction
        let mut lowest_gas_limit = gas_used.saturating_sub(1);

        // As stated in Geth, there is a good chance that the transaction will pass if we set the
        // gas limit to the execution gas used plus the gas refund, so we check this first
        // <https://github.com/ethereum/go-ethereum/blob/a5a4fa7032bb248f5a7c40f4e8df2b131c4186a4/eth/gasestimator/gasestimator.go#L135
        //
        // Calculate the optimistic gas limit by adding gas used and gas refund,
        // then applying a 64/63 multiplier to account for gas forwarding rules.
        let optimistic_gas_limit = (gas_used + gas_refund + CALL_STIPEND_GAS) * 64 / 63;
        if optimistic_gas_limit < highest_gas_limit {
            // Set the transaction's gas limit to the calculated optimistic gas limit.
            tx_env.set_gas_limit(optimistic_gas_limit);
            // Re-execute the transaction with the new gas limit and update the result and
            // environment.
            (res, (evm_env, tx_env)) = self.transact(&mut db, evm_env, tx_env)?;
            // Update the gas used based on the new result.
            gas_used = res.result.gas_used();
            // Update the gas limit estimates (highest and lowest) based on the execution result.
            update_estimated_gas_range(
                res.result,
                optimistic_gas_limit,
                &mut highest_gas_limit,
                &mut lowest_gas_limit,
            )?;
        };

        // Pick a point that's close to the estimated gas
        let mut mid_gas_limit = std::cmp::min(
            gas_used * 3,
            ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64,
        );

        trace!(target: "rpc::eth::estimate", ?evm_env, ?tx_env, ?highest_gas_limit, ?lowest_gas_limit, ?mid_gas_limit, "Starting binary search for gas");

        // Binary search narrows the range to find the minimum gas limit needed for the transaction
        // to succeed.
        while lowest_gas_limit + 1 < highest_gas_limit {
            // An estimation error is allowed once the current gas limit range used in the binary
            // search is small enough (less than 1.5% of the highest gas limit)
            // <https://github.com/ethereum/go-ethereum/blob/a5a4fa7032bb248f5a7c40f4e8df2b131c4186a4/eth/gasestimator/gasestimator.go#L152
            if (highest_gas_limit - lowest_gas_limit) as f64 / (highest_gas_limit as f64) <
                ESTIMATE_GAS_ERROR_RATIO
            {
                break
            };

            tx_env.set_gas_limit(mid_gas_limit);

            // Execute transaction and handle potential gas errors, adjusting limits accordingly.
            match self.transact(&mut db, evm_env.clone(), tx_env.clone()) {
                Err(err) if err.is_gas_too_high() => {
                    // Decrease the highest gas limit if gas is too high
                    highest_gas_limit = mid_gas_limit;
                }
                Err(err) if err.is_gas_too_low() => {
                    // Increase the lowest gas limit if gas is too low
                    lowest_gas_limit = mid_gas_limit;
                }
                // Handle other cases, including successful transactions.
                ethres => {
                    // Unpack the result and environment if the transaction was successful.
                    (res, (evm_env, tx_env)) = ethres?;
                    // Update the estimated gas range based on the transaction result.
                    update_estimated_gas_range(
                        res.result,
                        mid_gas_limit,
                        &mut highest_gas_limit,
                        &mut lowest_gas_limit,
                    )?;
                }
            }

            // New midpoint
            mid_gas_limit = ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64;
        }

        Ok(U256::from(highest_gas_limit))
    }
}

impl<N> Call for SeismicEthApi<N>
where
    Self: LoadState<
            Evm: ConfigureEvm<
                Primitives: NodePrimitives<
                    BlockHeader = ProviderHeader<Self::Provider>,
                    SignedTx = ProviderTx<Self::Provider>,
                >,
                BlockExecutorFactory: BlockExecutorFactory<
                    EvmFactory: EvmFactory<Tx = seismic_revm::SeismicTransaction<TxEnv>>,
                >,
            >,
            Error: FromEvmError<Self::Evm>,
        > + SpawnBlocking,
    Self::Error: From<EthApiError>,
    N: SeismicNodeCore,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    fn create_txn_env(
        &self,
        evm_env: &EvmEnv<SpecFor<Self::Evm>>,
        request: TransactionRequest,
        mut db: impl Database<Error: Into<EthApiError>>,
    ) -> Result<SeismicTransaction<TxEnv>, Self::Error> {
        // Ensure that if versioned hashes are set, they're not empty
        if request.blob_versioned_hashes.as_ref().is_some_and(|hashes| hashes.is_empty()) {
            return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into_eth_err())
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
            )?;

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
            nonce
        } else {
            db.basic(caller).map_err(Into::into)?.map(|acc| acc.nonce).unwrap_or_default()
        };

        let authorization_list: Vec<Either<SignedAuthorization, RecoveredAuthorization>> =
            authorization_list
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
                .try_into_unique_input()
                .map_err(Self::Error::from_eth_err)?
                .unwrap_or_default(),
            chain_id: Some(chain_id),
            access_list: access_list.unwrap_or_default(),
            // EIP-4844 fields
            blob_hashes: blob_versioned_hashes.unwrap_or_default(),
            max_fee_per_blob_gas: max_fee_per_blob_gas
                .map(|v| v.saturating_to())
                .unwrap_or_default(),
            // EIP-7702 fields
            authorization_list,
        };

        debug!("reth-seismic-rpc::eth create_txn_env {:?}", env);

        Ok(SeismicTransaction {
            base: env,
            tx_hash: Default::default(),
            rng_mode: RngMode::Simulation,
        })
    }
}

/// Gets the gas allowance from the seismic gas contract
fn seismic_caller_gas_allowance<DB>(db: &mut DB, env: &impl TransactionEnv) -> EthResult<u64>
where
    DB: Database,
    EthApiError: From<<DB as Database>::Error>,
{

    let caller = env.caller();
    let caller_gas_key = seismic_revm::src20_gas::gas_caller_key(caller);
    let balance = db.storage(seismic_revm::src20_gas::GAS_SRC20_ADDRESS, caller_gas_key)?.value;

    Ok(balance
        // Calculate the amount of gas the caller can afford with the specified gas price.
        .checked_div(U256::from(env.gas_price()))
        // This will be 0 if gas price is 0. It is fine, because we check it before.
        .unwrap_or_default()
        .saturating_to())
}