//! Seismic rpc logic.
//!
//! `seismic_` namespace overrides:
//!
//! - `seismic_getTeePublicKey` will return the public key of the Seismic enclave.
//!
//! `eth_` namespace overrides:
//!
//! - `eth_signTypedData_v4` will sign a typed data request using the Seismic enclave.

use super::api::FullSeismicApi;
use crate::{
    error::SeismicEthApiError,
    utils::{
        convert_seismic_call_to_tx_request,
        seismic_override_call_request,
    },
};
use alloy_dyn_abi::TypedData;
use alloy_json_rpc::RpcObject;
use alloy_primitives::{Address, Bytes, B256};
use alloy_rpc_types::{
    state::{EvmOverrides, StateOverride},
    BlockId, BlockOverrides,
};
use futures::Future;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_node_core::node_config::NodeConfig;
use reth_rpc_eth_api::{
    helpers::{EthCall, EthTransactions},
    RpcBlock,
};
use reth_rpc_eth_types::{utils::recover_raw_transaction};
use reth_tracing::tracing::*;
use seismic_alloy_consensus::{Decodable712, SeismicTxEnvelope, TypedDataRequest};
use seismic_alloy_rpc_types::{
    SeismicCallRequest, SeismicRawTxRequest, SeismicTransactionRequest,
    SimBlock as SeismicSimBlock, SimulatePayload as SeismicSimulatePayload,
};
use seismic_enclave::{
    rpc::EnclaveApiClient, EnclaveClient, PublicKey,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use reth_rpc_eth_types::EthApiError;
use alloy_rpc_types_eth::simulate::{SimBlock as EthSimBlock, SimulatePayload as EthSimulatePayload, SimulatedBlock};
use alloy_rpc_types::TransactionRequest;

/// trait interface for a custom rpc namespace: `seismic`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "seismic"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "seismic"))]
pub trait SeismicApi {
    /// Returns the network public key
    #[method(name = "getTeePublicKey")]
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey>;
}

/// Implementation of the seismic rpc api
#[derive(Debug, Default)]
pub struct SeismicApi {
    enclave_client: EnclaveClient,
}

impl SeismicApi {
    /// Creates a new seismic api instance
    pub fn new<ChainSpec>(config: &NodeConfig<ChainSpec>) -> Self {
        Self {
            enclave_client: EnclaveClient::builder()
                .addr(config.enclave.enclave_server_addr.to_string())
                .port(config.enclave.enclave_server_port)
                .timeout(std::time::Duration::from_secs(config.enclave.enclave_timeout))
                .build(),
        }
    }

    /// Creates a new seismic api instance with an enclave client
    pub fn with_enclave_client(mut self, enclave_client: EnclaveClient) -> Self {
        self.enclave_client = enclave_client;
        self
    }
}

#[async_trait]
impl SeismicApiServer for SeismicApi {
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey> {
        trace!(target: "rpc::seismic", "Serving seismic_getTeePublicKey");
        self.enclave_client
            .get_public_key()
            .await
            .map_err(|e| SeismicEthApiError::EnclaveError(e.to_string()).into())
    }
}

/// Localhost with port 0 so a free port is used.
pub const fn test_address() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

/// Extension trait for `EthTransactions` to add custom transaction sending functionalities.
pub trait SeismicTransaction: EthTransactions {
    /// Decodes, signs (if necessary via an internal signer or enclave),
    /// and submits a typed data transaction to the pool.
    /// Returns the hash of the transaction.
    fn send_typed_data_transaction(
        &self,
        tx_request: TypedDataRequest,
    ) -> impl Future<Output = Result<B256, Self::Error>> + Send;
}

/// Seismic `eth_` RPC namespace overrides.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "eth"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride<B: RpcObject> {
    /// Returns the account and storage values of the specified account including the Merkle-proof.
    /// This call can be used to verify that the data you are pulling from is not tampered with.
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

    /// Sends signed transaction, returning its hash.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, bytes: SeismicRawTxRequest) -> RpcResult<B256>;
}

/// Implementation of the `eth_` namespace override
#[derive(Debug)]
pub struct EthApiExt<Eth> {
    eth_api: Eth,
    enclave_client: EnclaveClient,
}

impl<Eth> EthApiExt<Eth> {
    /// Create a new `EthApiExt` module.
    pub const fn new(eth_api: Eth, enclave_client: EnclaveClient) -> Self {
        Self { eth_api, enclave_client }
    }
}

#[async_trait]
impl<Eth> EthApiOverrideServer<RpcBlock<Eth::NetworkTypes>> for EthApiExt<Eth>
where
    Eth: FullSeismicApi,
    jsonrpsee_types::error::ErrorObject<'static>: From<Eth::Error>,
{
    /// Handler for: `eth_signTypedData_v4`
    async fn sign_typed_data_v4(&self, from: Address, data: TypedData) -> RpcResult<String> {
        trace!(target: "rpc::eth", "Serving eth_signTypedData_v4");
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
        trace!(target: "rpc::eth", "Serving eth_simulateV1");

        let seismic_sim_blocks: Vec<SeismicSimBlock<SeismicCallRequest>> =
            payload.block_state_calls.clone();

        // Recover EthSimBlocks from the SeismicSimulatePayload<SeismicCallRequest>
        let mut eth_simulated_blocks: Vec<EthSimBlock> =
            Vec::with_capacity(payload.block_state_calls.len());
        for block in payload.block_state_calls {
            let SeismicSimBlock { block_overrides, state_overrides, calls } = block;
            let mut prepared_calls = Vec::with_capacity(calls.len());

            for call in calls {
                let seismic_tx_request = convert_seismic_call_to_tx_request(call)?;
                let tx_request: TransactionRequest = seismic_tx_request.inner;
                prepared_calls.push(tx_request);
            }

            let prepared_block =
                EthSimBlock { block_overrides, state_overrides, calls: prepared_calls };

            eth_simulated_blocks.push(prepared_block);
        }

        // Call Eth simulate_v1, which only takes EthSimPayload/EthSimBlock
        let result = EthCall::simulate_v1(
            &self.eth_api,
            EthSimulatePayload {
                block_state_calls: eth_simulated_blocks.clone(),
                trace_transfers: payload.trace_transfers,
                validation: payload.validation,
                return_full_transactions: payload.return_full_transactions,
            },
            block_number,
        )
        .await;
        let mut result = result.unwrap();

        // Convert Eth Blocks back to Seismic blocks
        // Includes encrypting the output? should it?
        for (block, result) in seismic_sim_blocks.iter().zip(result.iter_mut()) {
            let SeismicSimBlock::<SeismicCallRequest> { calls, .. } = block;
            let SimulatedBlock { calls: call_results, .. } = result;

            for (call_result, call) in call_results.iter_mut().zip(calls.iter()) {
                let seismic_tx_request = convert_seismic_call_to_tx_request(call.clone())?;
                let seismic_elements = seismic_tx_request.seismic_elements.clone();

                let enclave_client = EnclaveClient::default();

                if let Some(seismic_elements) = seismic_elements {
                    let encrypted_output = seismic_elements
                        .server_encrypt(&enclave_client, &call_result.return_data)
                        .map_err(|e| {
                            EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
                                -32000, // TODO: pick a better error code?
                                "EncryptionError",
                                Some(e.to_string()),
                            )))
                        })?;
                    call_result.return_data = encrypted_output;
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
        debug!(target: "rpc::eth", ?request, ?block_number, ?state_overrides, ?block_overrides, "Serving overridden eth_call");
        let seismic_tx_request: SeismicTransactionRequest = match request {
            SeismicCallRequest::TransactionRequest(mut tx_request) => {
                seismic_override_call_request(&mut tx_request.inner);
                tx_request
            }

            SeismicCallRequest::TypedData(typed_request) => {
                SeismicTransactionRequest::decode_712(&typed_request).unwrap()
            }

            SeismicCallRequest::Bytes(bytes) => {
                let tx = recover_raw_transaction::<SeismicTxEnvelope>(&bytes)?;
                tx.inner().clone().into()
            }
        };

        let result = EthCall::call(
            &self.eth_api,
            seismic_tx_request.inner,
            block_number,
            EvmOverrides::new(state_overrides, block_overrides),
        )
        .await?;

        // if let Some(seismic_elements) = seismic_elements {
        //     return Ok(seismic_elements.server_encrypt(&self.enclave_client, &result).unwrap());
        // } else {
        //     Ok(result)
        // }
        Ok(result)
    }

    /// Handler for: `eth_sendRawTransaction`
    async fn send_raw_transaction(&self, tx: SeismicRawTxRequest) -> RpcResult<B256> {
        trace!(target: "rpc::eth", ?tx, "Serving overridden eth_sendRawTransaction");
        match tx {
            SeismicRawTxRequest::Bytes(bytes) => {
                Ok(EthTransactions::send_raw_transaction(&self.eth_api, bytes).await?)
            }
            SeismicRawTxRequest::TypedData(typed_data) => {
                Ok(SeismicTransaction::send_typed_data_transaction(&self.eth_api, typed_data)
                    .await?)
            }
        }
    }
}
