//! seismic implementation of eth api and its extensions
//!
//! Overrides the eth_ namespace to be compatible with seismic specific types
//! Most endpoints handle transaction decrytpion before passing to the inner eth api
//! For `eth_sendRawTransaction`, we directly call the inner eth api without decryption
//! See that function's docs for more details

use crate::utils::{
    convert_seismic_call_to_tx_request, parse_request_sender, signed_read_to_plaintext_tx,
};
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
    Bundle, EthCallResponse, StateContext,
};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_network_api::PeersInfo;
use reth_network_peers::NodeRecord;
use reth_rpc_eth_api::{
    helpers::{EthCall, EthTransactions, FullEthApi},
    RpcBlock, RpcTypes,
};
use reth_rpc_eth_types::EthApiError;
use reth_tracing::tracing::*;
use seismic_alloy_consensus::{
    Decodable712, InputDecryptionElements, SeismicTxEnvelope, TxSeismicMetadata,
};
use seismic_alloy_rpc_types::{
    SeismicCallRequest, SeismicRawTxRequest, SeismicTransactionRequest,
    SimBlock as SeismicSimBlock, SimulatePayload as SeismicSimulatePayload,
};
use seismic_enclave::{secp256k1::PublicKey, GetPurposeKeysResponse};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

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
    purpose_keys: GetPurposeKeysResponse,
    // Keep the PeersInfo provider instead of snapshotting a NodeRecord because discovery
    // may update the externally advertised address after startup.
    peers_info: P,
}

impl<P: PeersInfo> SeismicApi<P> {
    /// Creates a new seismic api instance.
    pub const fn new(purpose_keys: GetPurposeKeysResponse, peers_info: P) -> Self {
        Self { purpose_keys, peers_info }
    }
}

#[async_trait]
impl<P: PeersInfo + 'static> SeismicApiServer for SeismicApi<P> {
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey> {
        trace!(target: "rpc::seismic", "Serving seismic_getTeePublicKey");
        Ok(self.purpose_keys.tx_io_pk)
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
}

/// Implementation of the `eth_` namespace override
#[derive(Debug, Clone)]
pub struct EthApiExt<Eth> {
    eth_api: Eth,
    purpose_keys: GetPurposeKeysResponse,
}

impl<Eth> EthApiExt<Eth> {
    /// Create a new `EthApiExt` module.
    pub const fn new(eth_api: Eth, purpose_keys: GetPurposeKeysResponse) -> Self {
        Self { eth_api, purpose_keys }
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
}

#[async_trait]
impl<Eth> EthApiOverrideServer<RpcBlock<Eth::NetworkTypes>> for EthApiExt<Eth>
where
    Eth: FullEthApi + Send + Sync + 'static,
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
                let tx_req = convert_seismic_call_to_tx_request(call)?;
                let plaintext_tx_req = signed_read_to_plaintext_tx(
                    tx_req,
                    &self.purpose_keys.tx_io_sk,
                    self.eth_api.provider(),
                )?;
                let tx_request: TransactionRequest = plaintext_tx_req.inner;
                prepared_calls.push(tx_request.into());
            }

            let prepared_block =
                EthSimBlock { block_overrides, state_overrides, calls: prepared_calls };

            eth_simulated_blocks.push(prepared_block);
        }

        // Call Eth simulate_v1, which only takes EthSimPayload/EthSimBlock
        let mut result = EthCall::simulate_v1(
            &self.eth_api,
            EthSimulatePayload {
                block_state_calls: eth_simulated_blocks.clone(),
                trace_transfers: payload.trace_transfers,
                validation: payload.validation,
                return_full_transactions: payload.return_full_transactions,
            },
            block_number,
        )
        .await?;

        // Convert Eth Blocks back to Seismic blocks
        for (block, result) in seismic_sim_blocks.iter().zip(result.iter_mut()) {
            let SeismicSimBlock::<SeismicCallRequest> { calls, .. } = block;
            let SimulatedBlock { calls: call_results, .. } = result;

            for (call_result, call) in call_results.iter_mut().zip(calls.iter()) {
                let (seismic_tx_request, signed_read) =
                    convert_seismic_call_to_tx_request(call.clone())?;
                if signed_read {
                    // if there are seismic elements, encrypt the output
                    let sender = parse_request_sender(&seismic_tx_request)?;
                    let metadata = Self::build_metadata(&seismic_tx_request, sender)?;
                    let encrypted_output = metadata
                        .encrypt(&self.purpose_keys.tx_io_sk, &call_result.return_data)
                        .map_err(|e| ext_encryption_error(e.to_string()))?;
                    call_result.return_data = encrypted_output;
                }
            }
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

        // Keep originals so we can encrypt return data per-call after the inner call_many.
        let seismic_bundles = bundles.clone();

        // Convert each Bundle<SeismicCallRequest> into the upstream Bundle<TransactionRequest>:
        // unsigned requests are sanitized; signed requests have their freshness validated and
        // calldata decrypted by `signed_read_to_plaintext_tx`.
        let mut prepared_bundles: Vec<Bundle<<Eth::NetworkTypes as RpcTypes>::TransactionRequest>> =
            Vec::with_capacity(bundles.len());
        for bundle in bundles {
            let Bundle { transactions, block_override } = bundle;
            let mut prepared = Vec::with_capacity(transactions.len());
            for call in transactions {
                let tx_req = convert_seismic_call_to_tx_request(call)?;
                let plaintext_tx_req = signed_read_to_plaintext_tx(
                    tx_req,
                    &self.purpose_keys.tx_io_sk,
                    self.eth_api.provider(),
                )?;
                let tx_request: TransactionRequest = plaintext_tx_req.inner;
                prepared.push(tx_request.into());
            }
            prepared_bundles.push(Bundle { transactions: prepared, block_override });
        }

        let mut result =
            EthCall::call_many(&self.eth_api, prepared_bundles, state_context, state_override)
                .await?;

        // Encrypt return data for signed-read calls so the response is readable only by the
        // signer (matches the single-call `eth_call` behavior).
        for (bundle, bundle_results) in seismic_bundles.iter().zip(result.iter_mut()) {
            for (call, call_result) in bundle.transactions.iter().zip(bundle_results.iter_mut()) {
                let (seismic_tx_request, signed_read) =
                    convert_seismic_call_to_tx_request(call.clone())?;
                if signed_read {
                    if let Some(value) = call_result.value.as_mut() {
                        let sender = parse_request_sender(&seismic_tx_request)?;
                        let metadata = Self::build_metadata(&seismic_tx_request, sender)?;
                        *value = metadata
                            .encrypt(&self.purpose_keys.tx_io_sk, value)
                            .map_err(|e| ext_encryption_error(e.to_string()))?;
                    }
                }
            }
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

        // process different CallRequest types
        let (seismic_tx_request, signed_read) = convert_seismic_call_to_tx_request(request)?;
        let plaintext_tx_req = signed_read_to_plaintext_tx(
            (seismic_tx_request.clone(), signed_read),
            &self.purpose_keys.tx_io_sk,
            self.eth_api.provider(),
        )?;

        // call inner
        let result = EthCall::call(
            &self.eth_api,
            plaintext_tx_req.inner.into(),
            block_number,
            EvmOverrides::new(state_overrides, block_overrides),
        )
        .await?;

        // encrypt result - only for signed reads with seismic elements
        if signed_read {
            if let Some(seismic_elements) = seismic_tx_request.seismic_elements {
                let sender = parse_request_sender(&seismic_tx_request)?;
                let metadata = Self::build_metadata(&seismic_tx_request, sender)?;
                return Ok(seismic_elements
                    .encrypt(&self.purpose_keys.tx_io_sk, &result, &metadata)
                    .map_err(|e| ext_encryption_error(e.to_string()))?);
            }
        }

        Ok(result)
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

        // Same sanitization as eth_call: unsigned requests have `from`,
        // gas/value fields, and seismic_elements cleared to prevent caller
        // spoofing that could leak private state. Signed requests (TypedData/Bytes)
        // authenticate the sender cryptographically and are processed normally.
        let (seismic_tx_request, signed_read) = convert_seismic_call_to_tx_request(request)?;
        let decrypted_req = signed_read_to_plaintext_tx(
            (seismic_tx_request, signed_read),
            &self.purpose_keys.tx_io_sk,
            self.eth_api.provider(),
        )?;

        // call inner
        Ok(EthCall::estimate_gas_at(
            &self.eth_api,
            decrypted_req.inner.into(),
            block_number.unwrap_or_default(),
            state_override,
        )
        .await?)
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

/// Creates an [`EthApiError`] that says that seismic encryption failed
pub fn ext_encryption_error(e_str: String) -> EthApiError {
    EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
        -32000, // TODO: pick a better error code?
        "Error Encrypting in Seismic EthApiExt",
        Some(e_str),
    )))
}
