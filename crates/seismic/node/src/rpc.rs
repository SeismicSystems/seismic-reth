use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use secp256k1::PublicKey;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tee_service_api::get_sample_secp256k1_pk;
use tracing::trace;

/// trait interface for a custom rpc namespace: `seismic`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "seismic"))]
#[cfg_attr(test, rpc(server, client, namespace = "seismic"))]
pub trait SeismicApi {
    /// Returns the number of transactions in the pool.
    #[method(name = "getTeePublicKey")]
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey>;
}

pub struct SeismicApi {}
impl SeismicApi {
    pub fn new() -> Self {
        Self {}
    }
}

/// Localhost with port 0 so a free port is used.
pub const fn test_address() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

#[async_trait]
impl SeismicApiServer for SeismicApi {
    async fn get_tee_public_key(&self) -> RpcResult<PublicKey> {
        trace!(target: "rpc::seismic", "Serving seismic_getTeePublicKey");
        Ok(get_sample_secp256k1_pk())
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::{core::client::{ClientT, SubscriptionClientT}, Methods};
    use reth_rpc_builder::{RpcServerConfig, RpcServerHandle, TransportRpcModules};

    use super::*;

    /// Launches a new server with http only with the given modules
    pub async fn launch_http(modules: impl Into<Methods>) -> RpcServerHandle {
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
