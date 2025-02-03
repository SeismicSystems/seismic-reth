//! Seismic rpc logic.
//!
//! `seismic_` namespace overrides:
//!
//! - `seismic_getTeePublicKey` will return the public key of the Seismic tee.
//!
//! `eth_` namespace overrides:
//!
//! - `eth_signTypedData_v4` will sign a typed data request using the Seismic tee.

use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, Bytes};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_rpc_eth_api::{
    helpers::{EthState, EthTransactions, FullEthApi},
    FromEthApiError, IntoEthApiError,
};
use reth_rpc_eth_types::{EthApiError, SignError};
use reth_tracing::tracing::*;
use secp256k1::PublicKey;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tee_service_api::get_sample_secp256k1_pk;

/// trait interface for a custom rpc namespace: `seismic`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "seismic"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "seismic"))]
pub trait SeismicApi {
    /// Returns the number of transactions in the pool.
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
        Ok(get_sample_secp256k1_pk())
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
    use jsonrpsee::{
        core::client::{ClientT, SubscriptionClientT},
        Methods,
    };
    use reth_rpc_builder::{RpcServerConfig, RpcServerHandle, TransportRpcModules};

    use super::*;

    /// Launches a new server with http only with the given modules
    pub(crate) async fn launch_http(modules: impl Into<Methods>) -> RpcServerHandle {
        let mut server = TransportRpcModules::default();
        let _ = server.merge_configured(modules);
        RpcServerConfig::http(Default::default())
            .with_http_address(test_address())
            .start(&server)
            .await
            .unwrap()
    }

    async fn test_basic_seismic_calls<C>(client: &C)
    where
        C: ClientT + SubscriptionClientT + Sync,
    {
        let pk = SeismicApiClient::get_tee_public_key(client).await.unwrap();
        assert_eq!(pk, get_sample_secp256k1_pk());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_seismic_functions_http() {
        reth_tracing::init_test_tracing();

        let seismic_api = SeismicApi::new();
        let handle = launch_http(seismic_api.into_rpc()).await;
        let client = handle.http_client().unwrap();
        test_basic_seismic_calls(&client).await;
    }
}
