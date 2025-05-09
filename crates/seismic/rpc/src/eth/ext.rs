//! Seismic rpc logic.
//!
//! `seismic_` namespace overrides:
//!
//! - `seismic_getTeePublicKey` will return the public key of the Seismic enclave.
//!
//! `eth_` namespace overrides:
//!
//! - `eth_signTypedData_v4` will sign a typed data request using the Seismic enclave.

use alloy_dyn_abi::TypedData;
use alloy_json_rpc::RpcObject;
use alloy_primitives::{Address, Bytes, B256};
use alloy_rpc_types::{
    simulate::SimBlock,
    state::{EvmOverrides, StateOverride},
    BlockId, BlockOverrides,
};
use alloy_rpc_types_eth::{
    simulate::{SimulatePayload, SimulatedBlock},
    transaction::{TransactionInput, TransactionRequest},
};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_node_core::node_config::NodeConfig;
use reth_rpc_eth_api::{
    helpers::{EthCall, EthTransactions, FullEthApi},
    RpcBlock,
};
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError};
use reth_tracing::tracing::*;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use seismic_alloy_consensus::TypedDataRequest;
use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicRawTxRequest, SeismicTransactionRequest};
use seismic_enclave::{
    rpc::EnclaveApiClient, serde::de, tx_io::IoDecryptionRequest, EnclaveClient, PublicKey,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::{
    error::SeismicApiError,
    utils::{recover_typed_data_request, seismic_override_call_request},
};
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
            .map_err(|e| SeismicApiError::EnclaveError(e.to_string()).into())
    }
}

/// Localhost with port 0 so a free port is used.
pub const fn test_address() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
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
    // #[method(name = "simulateV1")]
    // async fn simulate_v1(
    //     &self,
    //     opts: SimulatePayload<SeismicCallRequest>,
    //     block_number: Option<BlockId>,
    // ) -> RpcResult<Vec<SimulatedBlock<B>>>;

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
    client: EnclaveClient,
}

impl<Eth> EthApiExt<Eth> {
    /// Create a new `EthApiExt` module.
    pub const fn new(eth_api: Eth, client: EnclaveClient) -> Self {
        Self { eth_api, client }
    }
}

#[async_trait]
impl<Eth> EthApiOverrideServer<RpcBlock<Eth::NetworkTypes>> for EthApiExt<Eth>
where
    Eth: FullEthApi,
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

    /// Handler for: `eth_simulateV1` TODO: fix this
    // async fn simulate_v1(
    //     &self,
    //     payload: SimulatePayload<SeismicCallRequest>,
    //     block_number: Option<BlockId>,
    // ) -> RpcResult<Vec<SimulatedBlock<RpcBlock<Eth::NetworkTypes>>>> {
    //     trace!(target: "rpc::eth", "Serving eth_simulateV1");

    //     let mut simulated_blocks = Vec::with_capacity(payload.block_state_calls.len());

    //     for block in payload.block_state_calls {
    //         let SimBlock { block_overrides, state_overrides, calls } = block;
    //         let mut prepared_calls: Vec<TransactionRequest> = Vec::with_capacity(calls.len());

    //         for call in calls {
    //             let tx_request = match call {
    //                 alloy_rpc_types::SeismicCallRequest::TransactionRequest(_tx_request) => {
    //                     return Err(EthApiError::InvalidParams(
    //                         "Invalid Transaction Request".to_string(),
    //                     )
    //                     .into())
    //                 }

    //                 alloy_rpc_types::SeismicCallRequest::TypedData(typed_request) => {
    //                     let tx =
    //
    // recover_typed_data_request::<PoolPooledTx<Eth::Pool>>(&typed_request)?
    // .map_transaction(                             <Eth::Pool as
    // TransactionPool>::Transaction::pooled_into_consensus,                         );

    //                     TransactionRequest::from_transaction_with_sender(
    //                         tx.as_signed().clone(),
    //                         tx.signer(),
    //                     )
    //                 }

    //                 alloy_rpc_types::SeismicCallRequest::Bytes(bytes) => {
    //                     let tx = recover_raw_transaction::<PoolPooledTx<Eth::Pool>>(&bytes)?
    //                         .map_transaction(
    //                             <Eth::Pool as
    // TransactionPool>::Transaction::pooled_into_consensus,                         );

    //                     TransactionRequest::from_transaction_with_sender(
    //                         tx.as_signed().clone(),
    //                         tx.signer(),
    //                     )
    //                 }
    //             };
    //             prepared_calls.push(tx_request);
    //         }

    //         let prepared_block =
    //             SimBlock { block_overrides, state_overrides, calls: prepared_calls };

    //         simulated_blocks.push(prepared_block);
    //     }

    //     let result = EthCall::simulate_v1(
    //         &self.eth_api,
    //         SimulatePayload {
    //             block_state_calls: simulated_blocks.clone(),
    //             trace_transfers: payload.trace_transfers,
    //             validation: payload.validation,
    //             return_full_transactions: payload.return_full_transactions,
    //         },
    //         block_number,
    //     )
    //     .await;
    //     let mut result = result.unwrap();

    //     for (block, result) in simulated_blocks.iter().zip(result.iter_mut()) {
    //         let SimBlock { calls, .. } = block;
    //         let SimulatedBlock { calls: call_results, .. } = result;

    //         for (call_result, call) in call_results.iter_mut().zip(calls.iter()) {
    //             call.seismic_elements.map(|seismic_elements| {
    //                 let encrypted_output = self
    //                     .eth_api
    //                     .evm_config()
    //                     .encrypt(&call_result.return_data, &seismic_elements)
    //                     .map(|encrypted_output| Bytes::from(encrypted_output))
    //                     .unwrap();
    //                 call_result.return_data = encrypted_output;
    //             });
    //         }
    //     }

    //     Ok(result)
    // }

    /// Handler for: `eth_call`
    async fn call(
        &self,
        request: SeismicCallRequest,
        block_number: Option<BlockId>,
        state_overrides: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes> {
        trace!(target: "rpc::eth", ?request, ?block_number, ?state_overrides, ?block_overrides, "Serving overridden eth_call");
        let tx_request: SeismicTransactionRequest = match request {
            SeismicCallRequest::TransactionRequest(tx_request) => tx_request,

            SeismicCallRequest::TypedData(typed_request) => {
                let tx = recover_typed_data_request::<PoolPooledTx<Eth::Pool>>(&typed_request)?;
                SeismicTransactionRequest::from_transaction_with_sender(
                    tx.inner().clone(),
                    tx.signer(),
                )
            }

            SeismicCallRequest::Bytes(bytes) => {
                // let tx = recover_raw_transaction::<PoolPooledTx<Eth::Pool>>(&bytes)?
                //     .map_transaction(
                //         <Eth::Pool as TransactionPool>::Transaction::pooled_into_consensus,
                //     );

                // TransactionRequest::from_transaction_with_sender(
                //     tx.inner().clone(),
                //     tx.signer(),
                // )
                todo!()
            }
        };

        // decrypt seismic elements
        let seismic_elements = tx_request.seismic_elements;
        let decrypted_data: Option<Vec<u8>> = None;
        if let Some(seismic_elements) = seismic_elements {
            let ciphertext = tx_request.inner.input.into_input().unwrap(); // Todo: figure out if

            let decrypted_data =
                seismic_elements.server_decrypt(&self.client, &ciphertext).map_err(|e| {
                    EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
                        -32000, // TODO: pick a better error code?
                        "DecryptionError",
                        Some(e.to_string()),
                    )))
                })?;
        }

        let result = Bytes::new();

        if let Some(seismic_elements) = seismic_elements {
            // let encrypted_output = self
            //     .eth_api
            //     .evm_config()
            //     .encrypt(&result, &seismic_elements)
            //     .map(|encrypted_output| Bytes::from(encrypted_output))
            //     .unwrap();
            // Ok(encrypted_output)
            todo!()
        } else {
            Ok(result)
        }
    }

    /// Handler for: `eth_sendRawTransaction`
    async fn send_raw_transaction(&self, tx: SeismicRawTxRequest) -> RpcResult<B256> {
        trace!(target: "rpc::eth", ?tx, "Serving overridden eth_sendRawTransaction");
        match tx {
            SeismicRawTxRequest::Bytes(bytes) => {
                // submits transaction to the tx pool
                Ok(EthTransactions::send_raw_transaction(&self.eth_api, bytes).await?)
            }
            SeismicRawTxRequest::TypedData(typed_data) => {
                todo!()
                // submits transaction to the tx pool
                // Ok(EthTransactions::send_typed_data_transaction(&self.eth_api,
                // typed_data).await?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{build_test_eth_api, launch_http};
    use alloy_primitives::{b256, hex, PrimitiveSignature};
    use alloy_rpc_types::Block;
    use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
    use reth_enclave::start_mock_enclave_server_random_port;
    use reth_provider::test_utils::MockEthProvider;
    use seismic_alloy_consensus::TypedDataRequest;
    use seismic_node::utils::test_utils::get_seismic_tx;

    use super::*;

    async fn test_basic_seismic_calls<C>(client: &C)
    where
        C: ClientT + SubscriptionClientT + Sync,
    {
        let _pk = SeismicApiClient::get_tee_public_key(client).await.unwrap();
    }

    async fn test_basic_eth_calls<C>(client: &C)
    where
        C: ClientT + SubscriptionClientT + Sync,
    {
        let typed_data = get_seismic_tx().eip712_to_type_data();
        let typed_data_request = TypedDataRequest {
            data: typed_data.clone(),
            signature: PrimitiveSignature::new(
                b256!("1fd474b1f9404c0c5df43b7620119ffbc3a1c3f942c73b6e14e9f55255ed9b1d").into(),
                b256!("29aca24813279a901ec13b5f7bb53385fa1fc627b946592221417ff74a49600d").into(),
                false,
            ),
        };
        let tx = Bytes::from(hex!("02f871018303579880850555633d1b82520894eee27662c2b8eba3cd936a23f039f3189633e4c887ad591c62bdaeb180c080a07ea72c68abfb8fca1bd964f0f99132ed9280261bdca3e549546c0205e800f7d0a05b4ef3039e9c9b9babc179a1878fb825b5aaf5aed2fa8744854150157b08d6f3"));
        let call_request = TransactionRequest::default();

        let _signature = EthApiOverrideClient::<Block>::sign_typed_data_v4(
            client,
            Address::ZERO,
            typed_data.clone(),
        )
        .await
        .unwrap_err();
        let _result = EthApiOverrideClient::<Block>::call(
            client,
            call_request.clone().into(),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        let _result =
            EthApiOverrideClient::<Block>::call(client, tx.clone().into(), None, None, None)
                .await
                .unwrap_err();
        let _result = EthApiOverrideClient::<Block>::call(
            client,
            typed_data_request.clone().into(),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        let _result =
            EthApiOverrideClient::<Block>::send_raw_transaction(client, tx.clone().into())
                .await
                .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_seismic_functions_http() {
        reth_tracing::init_test_tracing();
        let enclave_client = start_mock_enclave_server_random_port().await;

        let seismic_api = SeismicApi::default().with_enclave_client(enclave_client);

        let handle = launch_http(seismic_api.into_rpc()).await;
        let client = handle.http_client().unwrap();
        test_basic_seismic_calls(&client).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_eth_functions_http() {
        reth_tracing::init_test_tracing();

        let eth_api = build_test_eth_api(MockEthProvider::default());
        let eth_api = EthApiExt::new(eth_api);
        let handle = launch_http(eth_api.into_rpc()).await;
        test_basic_eth_calls(&handle.http_client().unwrap()).await;
    }
}
