//! seismic implementation of eth api and its extensions
//!
//! Overrides the eth_ namespace to be compatible with seismic specific types
//! Most endpoints handle transaction decrytpion before passing to the inner eth api
//! For `eth_sendRawTransaction`, we directly call the inner eth api without decryption
//! See that function's docs for more details

use crate::utils::{
    parse_request_sender, resolve_seismic_call, seismic_call_to_plaintext_tx, SeismicCall,
};
use alloy_consensus::proofs::calculate_transaction_root;
use alloy_dyn_abi::TypedData;
use alloy_eips::eip2718::Encodable2718;
use alloy_json_rpc::RpcObject;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types::{
    state::{EvmOverrides, StateOverride},
    BlockId, BlockOverrides, TransactionRequest,
};
use alloy_rpc_types_eth::{
    simulate::{SimBlock as EthSimBlock, SimulatePayload as EthSimulatePayload, SimulatedBlock},
    AccountInfo, Bundle, EthCallResponse, StateContext,
};
use alloy_seismic_evm::secp256k1::{PublicKey, SecretKey};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_network_api::PeersInfo;
use reth_network_peers::NodeRecord;
use reth_primitives_traits::{Recovered, RecoveredBlock};
use reth_rpc_eth_api::{
    helpers::{EthCall, EthState, EthTransactions, FullEthApi},
    AsEthApiError, FromEthApiError, RpcBlock, RpcTypes,
};
use reth_rpc_eth_types::{
    simulate::SimulatedBlockExecution, EthApiError, RevertError, RpcInvalidTransactionError,
};
use reth_seismic_keys::PurposeKeyring;
use reth_seismic_primitives::{SeismicPrimitives, SeismicTransactionSigned};
use reth_seismic_txpool::usdc::effective_balance;
use reth_tracing::tracing::*;
use seismic_alloy_consensus::{
    Decodable712, InputDecryptionElements, SeismicTxEnvelope, SeismicTypedTransaction,
    TxSeismicMetadata,
};
use seismic_alloy_rpc_types::{
    SeismicCallRequest, SeismicRawTxRequest, SeismicTransactionRequest,
    SimBlock as SeismicSimBlock, SimulatePayload as SeismicSimulatePayload,
};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

/// trait interface for a custom rpc namespace: `seismic`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "seismic"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "seismic"))]
pub trait SeismicApi {
    /// Returns the network public key.
    #[method(name = "getTeePublicKey")]
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey>;

    /// `admin` namespace is disabled for safety, but we still need the enode exposed for new
    /// joining nodes wanting to locate discv5 bootnodes. Operators starting new nodes who have
    /// the IP address of bootstrap nodes can query this endpoint for their enode record and add
    /// it to reth's startup config via `--bootnodes <ENODE>[,<ENODE>...]`.
    #[method(name = "nodeInfo")]
    async fn node_info(&self) -> RpcResult<SeismicNodeInfo>;
}

/// Public devp2p information for a Seismic node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeismicNodeInfo {
    /// The structured local node record, serialized as an enode URL.
    #[serde(rename = "enode")]
    pub node_record: NodeRecord,
}

/// Implementation of the seismic rpc api
#[derive(Debug, Clone)]
pub struct SeismicApi<P> {
    // Read through the keyring (not a key snapshot) so the advertised key follows
    // rotations at runtime.
    keyring: Arc<PurposeKeyring>,
    // Keep the PeersInfo provider instead of snapshotting a NodeRecord because discovery
    // may update the externally advertised address after startup.
    peers_info: P,
}

impl<P: PeersInfo> SeismicApi<P> {
    /// Creates a new seismic api instance.
    pub const fn new(keyring: Arc<PurposeKeyring>, peers_info: P) -> Self {
        Self { keyring, peers_info }
    }
}

#[async_trait]
impl<P: PeersInfo + 'static> SeismicApiServer for SeismicApi<P> {
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey> {
        trace!(target: "rpc::seismic", "Serving seismic_getTeePublicKey");
        let (_, keys) = self.keyring.current().map_err(keyring_unavailable_error)?;
        Ok(keys.tx_io.public_key())
    }

    async fn node_info(&self) -> RpcResult<SeismicNodeInfo> {
        trace!(target: "rpc::seismic", "Serving seismic_nodeInfo");
        Ok(SeismicNodeInfo { node_record: self.peers_info.local_node_record() })
    }
}

/// Localhost with port 0 so a free port is used.
pub const fn test_address() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

/// Seismic `eth_` RPC namespace overrides.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "eth"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride<B: RpcObject> {
    /// Signs the given EIP-712 typed structured data for the specified address and returns the
    /// resulting signature.
    #[method(name = "signTypedData_v4")]
    async fn sign_typed_data_v4(&self, address: Address, data: TypedData) -> RpcResult<String>;

    /// `eth_simulateV1` executes an arbitrary number of transactions on top of the requested state.
    /// The transactions are packed into individual blocks. Overrides can be provided.
    #[method(name = "simulateV1")]
    async fn simulate_v1(
        &self,
        opts: SeismicSimulatePayload<SeismicCallRequest>,
        block_number: Option<BlockId>,
    ) -> RpcResult<Vec<SimulatedBlock<B>>>;

    /// Executes a new message call immediately without creating a transaction on the block chain.
    #[method(name = "call")]
    async fn call(
        &self,
        request: SeismicCallRequest,
        block_number: Option<BlockId>,
        state_overrides: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes>;

    /// Simulate arbitrary number of transactions at an arbitrary blockchain index, with the
    /// optionality of state overrides.
    #[method(name = "callMany")]
    async fn call_many(
        &self,
        bundles: Vec<Bundle<SeismicCallRequest>>,
        state_context: Option<StateContext>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<Vec<Vec<EthCallResponse>>>;

    /// Sends signed transaction, returning its hash.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, bytes: SeismicRawTxRequest) -> RpcResult<B256>;

    /// Generates and returns an estimate of how much gas is necessary to allow the transaction to
    /// complete.
    #[method(name = "estimateGas")]
    async fn estimate_gas(
        &self,
        request: SeismicCallRequest,
        block_number: Option<BlockId>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<U256>;

    /// Returns the balance of an account. Defaults to the native balance (standard behavior).
    /// Pass `include_gas_token = true` to instead return the Seismic effective balance
    /// `max(native, usdc·10^12)`, which accounts for the USDC stablecoin accepted as gas.
    #[method(name = "getBalance")]
    async fn get_balance(
        &self,
        address: Address,
        block_number: Option<BlockId>,
        include_gas_token: Option<bool>,
    ) -> RpcResult<U256>;

    /// Returns `{balance, nonce, code}` for an account. The `balance` field defaults to the
    /// native balance (standard behavior). Pass `include_gas_token = true` to instead report
    /// the Seismic effective balance `max(native, usdc·10^12)`, mirroring the opt-in on
    /// `eth_getBalance`.
    #[method(name = "getAccountInfo")]
    async fn get_account_info(
        &self,
        address: Address,
        block: BlockId,
        include_gas_token: Option<bool>,
    ) -> RpcResult<AccountInfo>;
}

/// Implementation of the `eth_` namespace override
#[derive(Debug, Clone)]
pub struct EthApiExt<Eth> {
    eth_api: Eth,
    keyring: Arc<PurposeKeyring>,
}

impl<Eth> EthApiExt<Eth> {
    /// Create a new `EthApiExt` module.
    pub const fn new(eth_api: Eth, keyring: Arc<PurposeKeyring>) -> Self {
        Self { eth_api, keyring }
    }

    /// The tx-io secret key active at the canonical tip. Signed reads always decrypt
    /// with the tip epoch — wallets encrypt to the currently advertised public key,
    /// and freshness validation already pins requests to the tip window.
    //
    // TODO(purpose-key rotation, spec §8): once activation enforcement lands, retry
    // AEAD failures once with the previous epoch's key within the freshness window
    // to smooth the boundary. Dead code until rotations can activate.
    fn tx_io_sk(&self) -> Result<SecretKey, EthApiError> {
        let (_, keys) = self
            .keyring
            .current()
            .map_err(|e| EthApiError::Other(Box::new(keyring_unavailable_error(e))))?;
        Ok(keys.tx_io.secret_key())
    }

    /// Build transaction metadata for encryption/decryption.
    /// Returns an error if required fields are missing.
    fn build_metadata(
        request: &SeismicTransactionRequest,
        sender: Address,
    ) -> Result<TxSeismicMetadata, EthApiError> {
        request.metadata(sender).map_err(|e| {
            EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
                -32602,
                format!("Failed to build seismic metadata: {}", e),
                None::<String>,
            )))
        })
    }

    /// Spawns a blocking task computing the effective balance, max(native, usdc·10^12), for
    /// `address` at `block_id` (latest if `None`).
    ///
    /// Kept out of the `#[async_trait]` handler bodies: rustc ≤1.91 (MSRV is 1.88) fails to
    /// infer the type of the closure-returning-async-block passed to `spawn_blocking_io_fut`
    /// inside the macro-desugared bodies (E0308), while this plain `impl Future` method — the
    /// same shape as the `EthState` overrides in `mod.rs` — compiles on all toolchains.
    fn spawn_effective_balance(
        &self,
        address: Address,
        block_id: Option<BlockId>,
        native: U256,
    ) -> impl Future<Output = Result<U256, Eth::Error>> + Send + use<'_, Eth>
    where
        Eth: FullEthApi,
    {
        self.eth_api.spawn_blocking_io_fut(move |this| async move {
            let state = this.state_at_block_id_or_latest(block_id).await?;
            Ok(effective_balance(&*state, &address, native))
        })
    }

    /// Re-encrypts the output bytes of a reverted call for a signed-read caller.
    ///
    /// A contract's revert data can embed arbitrary values from private state (e.g. a custom
    /// error like `revert InsufficientBalance(actualBalance)`), just like a successful return
    /// value can. For signed reads, `err` is re-wrapped with the revert output bytes encrypted
    /// under the caller's key (mirroring the encryption already applied to successful output),
    /// so a revert can't be used to exfiltrate private state in cleartext.
    ///
    /// Non-revert errors, and reverts with empty output, are returned unchanged.
    fn reencrypt_revert_output<E>(
        &self,
        err: E,
        seismic_tx_request: &SeismicTransactionRequest,
    ) -> Result<E, EthApiError>
    where
        E: AsEthApiError + FromEthApiError,
    {
        let Some(EthApiError::InvalidTransaction(RpcInvalidTransactionError::Revert(revert))) =
            err.as_err()
        else {
            return Ok(err);
        };
        let Some(output) = revert.output() else {
            return Ok(err);
        };

        let sender = parse_request_sender(seismic_tx_request)?;
        let metadata = Self::build_metadata(seismic_tx_request, sender)?;
        let encrypted = metadata
            .encrypt_response(&self.tx_io_sk()?, output)
            .map_err(|e| ext_encryption_error(e.to_string()))?;

        Ok(E::from_eth_err(EthApiError::InvalidTransaction(RpcInvalidTransactionError::Revert(
            RevertError::new(encrypted),
        ))))
    }
}

/// Rebuilds a simulated signed-read transaction with its original ciphertext input so the
/// response hash is recomputed from the bytes returned to the client.
fn rebuild_simulated_signed_read_tx(
    tx: Recovered<SeismicTransactionSigned>,
    ciphertext_input: Bytes,
) -> Result<Recovered<SeismicTransactionSigned>, EthApiError> {
    let (signed_tx, signer) = tx.into_parts();
    let (mut typed_tx, signature) = signed_tx.split();
    match &mut typed_tx {
        SeismicTypedTransaction::Legacy(tx) => tx.input = ciphertext_input,
        SeismicTypedTransaction::Eip2930(tx) => tx.input = ciphertext_input,
        SeismicTypedTransaction::Eip1559(tx) => tx.input = ciphertext_input,
        SeismicTypedTransaction::Eip4844(tx) => tx.input = ciphertext_input,
        SeismicTypedTransaction::Eip7702(tx) => tx.input = ciphertext_input,
        SeismicTypedTransaction::Seismic(tx) => tx.input = ciphertext_input,
    }

    Ok(Recovered::new_unchecked(
        SeismicTransactionSigned::new_unhashed(typed_tx, signature),
        signer,
    ))
}

/// Reconstructs raw simulated blocks so their bodies and headers commit to the ciphertext-backed
/// transactions returned to signed-read callers.
///
/// Execution results remain those produced by the plaintext transactions. For consecutive
/// simulated blocks, each reconstructed header is linked to the hash of the preceding
/// reconstructed block.
fn reconstruct_simulated_blocks<Halt>(
    seismic_sim_blocks: &[SeismicSimBlock<SeismicCallRequest>],
    raw_results: Vec<SimulatedBlockExecution<SeismicPrimitives, Halt>>,
) -> Result<Vec<SimulatedBlockExecution<SeismicPrimitives, Halt>>, EthApiError> {
    if seismic_sim_blocks.len() != raw_results.len() {
        return Err(EthApiError::InternalEthError)
    }

    let mut reconstructed = Vec::with_capacity(raw_results.len());
    let mut parent_hash = None;

    for (sim_block, execution) in seismic_sim_blocks.iter().zip(raw_results) {
        if sim_block.calls.len() != execution.block.body().transactions.len() {
            return Err(EthApiError::InternalEthError)
        }

        let mut response_transactions = Vec::with_capacity(sim_block.calls.len());
        for (call, executed_tx) in
            sim_block.calls.iter().zip(execution.block.clone_transactions_recovered())
        {
            let response_tx = match resolve_seismic_call(call.clone())? {
                SeismicCall::Transparent(_) => executed_tx,
                SeismicCall::SignedRead(request) => {
                    let ciphertext_input = request.inner.input.input.clone().ok_or_else(|| {
                        EthApiError::InvalidParams(
                            "signed-read simulate transaction missing input".to_string(),
                        )
                    })?;
                    rebuild_simulated_signed_read_tx(executed_tx, ciphertext_input)?
                }
            };
            response_transactions.push(response_tx);
        }

        let (mut response_block, senders) = execution.block.split();
        response_block.body.transactions =
            response_transactions.into_iter().map(|tx| tx.into_parts().0).collect();
        if let Some(parent_hash) = parent_hash {
            response_block.header.parent_hash = parent_hash;
        }
        response_block.header.transactions_root =
            calculate_transaction_root(&response_block.body.transactions);

        let response_block = RecoveredBlock::new_unhashed(response_block, senders);
        parent_hash = Some(response_block.hash());
        reconstructed
            .push(SimulatedBlockExecution { block: response_block, results: execution.results });
    }

    Ok(reconstructed)
}

#[async_trait]
impl<Eth> EthApiOverrideServer<RpcBlock<Eth::NetworkTypes>> for EthApiExt<Eth>
where
    Eth: FullEthApi<Primitives = SeismicPrimitives> + Send + Sync + 'static,
    Eth::Error: Send + Sync + 'static,
    jsonrpsee_types::error::ErrorObject<'static>: From<Eth::Error>,
    <Eth::NetworkTypes as RpcTypes>::TransactionRequest:
        From<TransactionRequest> + AsRef<TransactionRequest> + Send + Sync + 'static,
{
    /// Handler for: `eth_signTypedData_v4`
    ///
    /// TODO: determine if this should be removed, seems the same as eth functionality
    async fn sign_typed_data_v4(&self, from: Address, data: TypedData) -> RpcResult<String> {
        debug!(target: "reth-seismic-rpc::eth", "Serving seismic eth_signTypedData_v4 extension");
        let signature = EthTransactions::sign_typed_data(&self.eth_api, &data, from)
            .map_err(|err| err.into())?;
        let signature = alloy_primitives::hex::encode(signature);
        Ok(format!("0x{signature}"))
    }

    /// Handler for: `eth_simulateV1`
    async fn simulate_v1(
        &self,
        payload: SeismicSimulatePayload<SeismicCallRequest>,
        block_number: Option<BlockId>,
    ) -> RpcResult<Vec<SimulatedBlock<RpcBlock<Eth::NetworkTypes>>>> {
        debug!(target: "reth-seismic-rpc::eth", "Serving seismic eth_simulateV1 extension");

        let trace_transfers = payload.trace_transfers;
        let validation = payload.validation;
        let return_full_transactions = payload.return_full_transactions;
        let tx_io_sk = self.tx_io_sk()?;
        let seismic_sim_blocks: Vec<SeismicSimBlock<SeismicCallRequest>> =
            payload.block_state_calls.clone();

        // Recover EthSimBlocks from the SeismicSimulatePayload<SeismicCallRequest>
        let mut eth_simulated_blocks: Vec<
            EthSimBlock<<Eth::NetworkTypes as RpcTypes>::TransactionRequest>,
        > = Vec::with_capacity(payload.block_state_calls.len());
        for block in payload.block_state_calls {
            let SeismicSimBlock { block_overrides, state_overrides, calls } = block;
            let mut prepared_calls = Vec::with_capacity(calls.len());

            for call in calls {
                let call = resolve_seismic_call(call)?;
                let plaintext_tx_req =
                    seismic_call_to_plaintext_tx(&call, &tx_io_sk, self.eth_api.provider())?;
                let tx_request: TransactionRequest = plaintext_tx_req.inner;
                prepared_calls.push(tx_request.into());
            }

            let prepared_block =
                EthSimBlock { block_overrides, state_overrides, calls: prepared_calls };

            eth_simulated_blocks.push(prepared_block);
        }

        // Execute the simulated blocks while keeping the structured block/results form so the
        // Seismic wrapper can rebuild the response transactions from ciphertext-backed inputs.
        let raw_results = EthCall::simulate_v1_raw(
            &self.eth_api,
            EthSimulatePayload {
                block_state_calls: eth_simulated_blocks,
                trace_transfers,
                validation,
                return_full_transactions,
            },
            block_number,
        )
        .await?;

        let raw_results = reconstruct_simulated_blocks(&seismic_sim_blocks, raw_results)?;

        let mut result = Vec::with_capacity(raw_results.len());

        // Convert reconstructed Seismic blocks into RPC blocks.
        for (block, execution) in seismic_sim_blocks.iter().zip(raw_results) {
            let SeismicSimBlock::<SeismicCallRequest> { calls, .. } = block;
            let mut simulated_block = reth_rpc_eth_types::simulate::build_simulated_block(
                execution.block,
                execution.results,
                return_full_transactions.into(),
                self.eth_api.tx_resp_builder(),
            )?;
            let SimulatedBlock { calls: call_results, .. } = &mut simulated_block;

            // Encrypt signed-read outputs and replace plaintext revert messages with the generic
            // form after the response block has been rebuilt with ciphertext-backed tx hashes.
            for (call_result, call) in call_results.iter_mut().zip(calls.iter()) {
                let SeismicCall::SignedRead(request) = resolve_seismic_call(call.clone())? else {
                    continue
                };

                // `build_simulated_block` sets a non-empty `return_data` only for
                // `ExecutionResult::Revert` (halts always leave it empty), and derives
                // `error.message` by decoding that same output as a revert reason. That
                // decoded reason can embed private state (e.g. a custom error like
                // `revert InsufficientBalance(actualBalance)`), so it must not reach the
                // client in cleartext. Replace it with a generic message: the caller can
                // still recover the real reason by decrypting `return_data` below.
                let is_revert_with_reason =
                    !call_result.status && !call_result.return_data.is_empty();

                let sender = parse_request_sender(&request)?;
                let metadata = Self::build_metadata(&request, sender)?;
                let encrypted_output = metadata
                    .encrypt_response(&tx_io_sk, &call_result.return_data)
                    .map_err(|e| ext_encryption_error(e.to_string()))?;
                call_result.return_data = encrypted_output;

                if is_revert_with_reason {
                    if let Some(error) = call_result.error.as_mut() {
                        error.message = "execution reverted".to_string();
                    }
                }
            }

            result.push(simulated_block);
        }

        Ok(result)
    }

    /// Handler for: `eth_callMany`
    async fn call_many(
        &self,
        bundles: Vec<Bundle<SeismicCallRequest>>,
        state_context: Option<StateContext>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<Vec<Vec<EthCallResponse>>> {
        debug!(target: "reth-seismic-rpc::eth", ?bundles, ?state_context, ?state_override, "Serving seismic eth_callMany extension");

        let tx_io_sk = self.tx_io_sk()?;
        // Keep originals so we can encrypt return data per-call after the inner call_many.
        let seismic_bundles = bundles.clone();

        // Convert each Bundle<SeismicCallRequest> into the upstream Bundle<TransactionRequest>:
        // unsigned requests are sanitized; signed requests have their freshness validated and
        // calldata decrypted by `seismic_call_to_plaintext_tx`.
        let mut prepared_bundles: Vec<Bundle<<Eth::NetworkTypes as RpcTypes>::TransactionRequest>> =
            Vec::with_capacity(bundles.len());
        for bundle in bundles {
            let Bundle { transactions, block_override } = bundle;
            let mut prepared = Vec::with_capacity(transactions.len());
            for call in transactions {
                let call = resolve_seismic_call(call)?;
                let plaintext_tx_req =
                    seismic_call_to_plaintext_tx(&call, &tx_io_sk, self.eth_api.provider())?;
                let tx_request: TransactionRequest = plaintext_tx_req.inner;
                prepared.push(tx_request.into());
            }
            prepared_bundles.push(Bundle { transactions: prepared, block_override });
        }

        // Use the raw per-call `Result` form so a revert's structured `RevertError` (and its
        // output bytes) is still available to re-encrypt below — the public `call_many` method
        // downgrades errors to a `String` immediately, which would discard them.
        let raw_results =
            EthCall::call_many_raw(&self.eth_api, prepared_bundles, state_context, state_override)
                .await?;

        // Encrypt return data (and re-encrypt revert output) for signed-read calls so the
        // response is readable only by the signer (matches the single-call `eth_call` behavior).
        let mut result: Vec<Vec<EthCallResponse>> = Vec::with_capacity(raw_results.len());
        for (bundle, bundle_results) in
            seismic_bundles.iter().filter(|bundle| !bundle.transactions.is_empty()).zip(raw_results)
        {
            let mut encrypted_bundle_results = Vec::with_capacity(bundle_results.len());
            for (call, call_result) in bundle.transactions.iter().zip(bundle_results) {
                let call = resolve_seismic_call(call.clone())?;

                let response = match (call, call_result) {
                    (SeismicCall::Transparent(_), Ok(value)) => {
                        EthCallResponse { value: Some(value), error: None }
                    }
                    (SeismicCall::Transparent(_), Err(err)) => {
                        EthCallResponse { value: None, error: Some(err.to_string()) }
                    }
                    (SeismicCall::SignedRead(request), Ok(mut value)) => {
                        let sender = parse_request_sender(&request)?;
                        let metadata = Self::build_metadata(&request, sender)?;
                        value = metadata
                            .encrypt_response(&tx_io_sk, &value)
                            .map_err(|e| ext_encryption_error(e.to_string()))?;
                        EthCallResponse { value: Some(value), error: None }
                    }
                    (SeismicCall::SignedRead(request), Err(err)) => {
                        // `EthCallResponse.error` is a plain string with no `data` field, so the
                        // encrypted revert output is appended as hex; otherwise the ciphertext
                        // would be dropped and the signer couldn't decrypt the revert reason.
                        let err = self.reencrypt_revert_output(err, &request)?;
                        let err_str = match err.as_err() {
                            Some(EthApiError::InvalidTransaction(
                                RpcInvalidTransactionError::Revert(revert),
                            )) => match revert.output() {
                                Some(output) => format!("execution reverted: {output}"),
                                None => err.to_string(),
                            },
                            _ => err.to_string(),
                        };
                        EthCallResponse { value: None, error: Some(err_str) }
                    }
                };
                encrypted_bundle_results.push(response);
            }
            result.push(encrypted_bundle_results);
        }

        Ok(result)
    }

    /// Handler for: `eth_call`
    async fn call(
        &self,
        request: SeismicCallRequest,
        block_number: Option<BlockId>,
        state_overrides: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes> {
        debug!(target: "reth-seismic-rpc::eth", ?request, ?block_number, ?state_overrides, ?block_overrides, "Serving seismic eth_call extension");

        let tx_io_sk = self.tx_io_sk()?;
        let call = resolve_seismic_call(request)?;
        let plaintext_tx_req = seismic_call_to_plaintext_tx(
            &call,
            &tx_io_sk,
            self.eth_api.provider(),
        )?;

        // call inner
        let result = EthCall::call(
            &self.eth_api,
            plaintext_tx_req.inner.into(),
            block_number,
            EvmOverrides::new(state_overrides, block_overrides),
        )
        .await;

        match call {
            SeismicCall::Transparent(_) => Ok(result?),
            SeismicCall::SignedRead(request) => {
                // On revert, re-encrypt the output bytes before they reach the client: a contract's
                // revert data can embed private state just like a successful return value can.
                let result = match result {
                    Err(err) => Err(self.reencrypt_revert_output(err, &request)?),
                    Ok(result) => Ok(result),
                }?;

                let sender = parse_request_sender(&request)?;
                let metadata = Self::build_metadata(&request, sender)?;
                Ok(metadata
                    .encrypt_response(&tx_io_sk, &result)
                    .map_err(|e| ext_encryption_error(e.to_string()))?)
            }
        }
    }

    /// Handler for: `eth_sendRawTransaction`
    ///
    /// Directly calls the inner eth api without decryption
    /// We do this so that it is encrypted in the tx pool, so it is encrypted in blocks
    /// decryption during execution is handled by the [`SeismicBlockExecutor`]
    async fn send_raw_transaction(&self, tx: SeismicRawTxRequest) -> RpcResult<B256> {
        debug!(target: "reth-seismic-rpc::eth", ?tx, "Serving overridden eth_sendRawTransaction extension");
        let bytes = match tx {
            SeismicRawTxRequest::Bytes(bytes) => bytes,
            SeismicRawTxRequest::TypedData(typed_data) => {
                // Re-encode EIP-712 typed-data submissions as RLP so they flow through
                // the same `Decodable2718` pipeline as raw-bytes submissions. This keeps
                // decode-time checks (e.g. signed-read rejection) uniformly enforced across all
                // signed-tx ingress paths.
                //
                // TODO(samlaf): we should update our clients to submit EIP-712 transactions as RLP
                // bytes directly rather than using the redundant `SeismicRawTxRequest::TypedData`
                // wrapper, and then delete this TypedData ingress path.
                let envelope = SeismicTxEnvelope::decode_712(&typed_data)
                    .map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;
                envelope.encoded_2718().into()
            }
        };
        Ok(EthTransactions::send_raw_transaction(&self.eth_api, bytes).await?)
    }

    async fn estimate_gas(
        &self,
        request: SeismicCallRequest,
        block_number: Option<BlockId>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<U256> {
        debug!(target: "reth-seismic-rpc::eth", ?request, ?block_number, ?state_override, "serving seismic eth_estimateGas extension");

        let tx_io_sk = self.tx_io_sk()?;
        // Same sanitization as eth_call: unsigned requests have `from`,
        // gas/value fields, and seismic_elements cleared to prevent caller
        // spoofing that could leak private state. Signed requests (TypedData/Bytes)
        // authenticate the sender cryptographically and must be call-only.
        let call = resolve_seismic_call(request)?;
        let decrypted_req = seismic_call_to_plaintext_tx(
            &call,
            &tx_io_sk,
            self.eth_api.provider(),
        )?;

        // call inner
        let result = EthCall::estimate_gas_at(
            &self.eth_api,
            decrypted_req.inner.into(),
            block_number.unwrap_or_default(),
            state_override,
        )
        .await;

        match call {
            SeismicCall::Transparent(_) => Ok(result?),
            SeismicCall::SignedRead(request) => {
                // On revert, re-encrypt the output bytes before they reach the client: a contract's
                // revert data can embed private state just like a successful return value can.
                let result = match result {
                    Err(err) => Err(self.reencrypt_revert_output(err, &request)?),
                    Ok(result) => Ok(result),
                }?;
                Ok(result)
            }
        }
    }

    async fn get_balance(
        &self,
        address: Address,
        block_number: Option<BlockId>,
        include_gas_token: Option<bool>,
    ) -> RpcResult<U256> {
        debug!(target: "reth-seismic-rpc::eth", ?address, ?block_number, ?include_gas_token, "Serving seismic eth_getBalance extension");

        // Default: native balance, matching standard eth_getBalance.
        let native = EthState::balance(&self.eth_api, address, block_number).await?;
        if include_gas_token != Some(true) {
            return Ok(native);
        }

        // Opt-in: effective balance, max(native, usdc·10^12).
        Ok(self.spawn_effective_balance(address, block_number, native).await?)
    }

    async fn get_account_info(
        &self,
        address: Address,
        block: BlockId,
        include_gas_token: Option<bool>,
    ) -> RpcResult<AccountInfo> {
        debug!(target: "reth-seismic-rpc::eth", ?address, ?block, ?include_gas_token, "Serving seismic eth_getAccountInfo extension");

        // Default: native balance, matching standard eth_getAccountInfo and eth_getBalance.
        let mut info = EthState::get_account_info(&self.eth_api, address, block).await?;
        if include_gas_token != Some(true) {
            return Ok(info);
        }

        // Opt-in: report the effective balance, max(native, usdc·10^12), in the balance field.
        let native = info.balance;
        info.balance = self.spawn_effective_balance(address, Some(block), native).await?;
        Ok(info)
    }
}

/// Creates an [`EthApiError`] that says that seismic decryption failed
pub fn ext_decryption_error(e_str: String) -> EthApiError {
    EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
        -32000, // TODO: pick a better error code?
        "Error Decrypting in Seismic EthApiExt",
        Some(e_str),
    )))
}

/// Error for a keyring that cannot serve the current epoch's keys (a rotation
/// activated before this node's custodian fetch completed).
pub fn keyring_unavailable_error(
    e: reth_seismic_keys::MissingEpochKeys,
) -> jsonrpsee_types::ErrorObjectOwned {
    jsonrpsee_types::ErrorObject::owned(
        -32000,
        "Purpose keys unavailable for the current epoch",
        Some(e.to_string()),
    )
}

/// Error for a failed encryption/decryption inside the Seismic `eth_` overrides.
pub fn ext_encryption_error(e_str: String) -> EthApiError {
    EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
        -32000, // TODO: pick a better error code?
        "Error Encrypting in Seismic EthApiExt",
        Some(e_str),
    )))
}
