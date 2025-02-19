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
use alloy_primitives::Address;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_rpc_eth_api::helpers::{EthTransactions, FullEthApi};
use reth_tracing::tracing::*;
use secp256k1::PublicKey;
use seismic_enclave::get_unsecure_sample_secp256k1_pk;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

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
#[derive(Debug)]
pub struct SeismicApi {}
impl SeismicApi {
    /// Creates a new seismic api instance
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl SeismicApiServer for SeismicApi {
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey> {
        trace!(target: "rpc::seismic", "Serving seismic_getTeePublicKey");
        Ok(get_unsecure_sample_secp256k1_pk())
    }
}

/// Localhost with port 0 so a free port is used.
pub const fn test_address() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

/// Seismic `eth_` RPC namespace overrides.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "eth"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    /// Returns the account and storage values of the specified account including the Merkle-proof.
    /// This call can be used to verify that the data you are pulling from is not tampered with.
    #[method(name = "signTypedData_v4")]
    async fn sign_typed_data_v4(&self, address: Address, data: TypedData) -> RpcResult<String>;
}

/// Implementation of the `eth_` namespace override
#[derive(Debug)]
pub struct EthApiExt<Eth> {
    eth_api: Eth,
}

impl<E> EthApiExt<E> {
    /// Create a new `EthApiExt` module.
    pub const fn new(eth_api: E) -> Self {
        Self { eth_api }
    }
}

#[async_trait]
impl<Eth> EthApiOverrideServer for EthApiExt<Eth>
where
    Eth: FullEthApi + Send + Sync + 'static,
{
    /// Handler for: `eth_signTypedData_v4`
    async fn sign_typed_data_v4(&self, from: Address, data: TypedData) -> RpcResult<String> {
        trace!(target: "rpc::eth", "Serving eth_signTypedData_v4");
        let signature = EthTransactions::sign_typed_data(&self.eth_api, &data, from)
            .map_err(|err| err.into())?;
        let signature = alloy_primitives::hex::encode(signature);
        Ok(format!("0x{signature}"))
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
    use reth_provider::test_utils::MockEthProvider;

    use crate::utils::test_utils::{build_test_eth_api, launch_http};
    use seismic_node::utils::test_utils::UnitTestContext;

    use super::*;

    async fn test_basic_seismic_calls<C>(client: &C)
    where
        C: ClientT + SubscriptionClientT + Sync,
    {
        let pk = SeismicApiClient::get_tee_public_key(client).await.unwrap();
        assert_eq!(pk, get_unsecure_sample_secp256k1_pk());
    }

    async fn test_basic_eth_calls<C>(client: &C)
    where
        C: ClientT + SubscriptionClientT + Sync,
    {
        let typed_data = UnitTestContext::get_seismic_tx().eip712_to_type_data();
        let _signature =
            EthApiOverrideClient::sign_typed_data_v4(client, Address::ZERO, typed_data)
                .await
                .unwrap_err();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_seismic_functions_http() {
        reth_tracing::init_test_tracing();

        let seismic_api = SeismicApi::new();
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
