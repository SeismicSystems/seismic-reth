use crate::{
    error::{RpcError, ServerKind},
    middleware::RethRpcMiddleware,
};
use jsonrpsee::{
    core::RegisterMethodError,
    server::{AlreadyStoppedError, RpcModule, ServerConfig, ServerConfigBuilder},
    ws_client::RpcServiceBuilder,
    Methods,
};
use reth_rpc_eth_types::EthSubscriptionIdProvider;
use reth_rpc_layer::{SignatureAuthConfig, SignatureAuthLayer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::layer::util::Identity;

pub use jsonrpsee::server::ServerBuilder;

/// Default port for the ops RPC server.
pub const DEFAULT_BODY_AUTH_PORT: u16 = 8552;

/// Server configuration for an RPC server authenticated via secp256k1 signatures.
#[derive(Debug)]
pub struct BodyAuthServerConfig<RpcMiddleware = Identity> {
    /// Where the server should listen.
    pub(crate) socket_addr: SocketAddr,
    /// Signature authentication configuration.
    pub(crate) auth_config: SignatureAuthConfig,
    /// Configs for JSON-RPC Http.
    pub(crate) server_config: ServerConfigBuilder,
    /// Configurable RPC middleware.
    pub(crate) rpc_middleware: RpcMiddleware,
}

impl BodyAuthServerConfig {
    /// Convenience function to create a new builder.
    pub const fn builder(auth_config: SignatureAuthConfig) -> BodyAuthServerConfigBuilder {
        BodyAuthServerConfigBuilder::new(auth_config)
    }
}

impl<RpcMiddleware> BodyAuthServerConfig<RpcMiddleware> {
    /// Returns the address the server will listen on.
    pub const fn address(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Configures the rpc middleware.
    pub fn with_rpc_middleware<T>(self, rpc_middleware: T) -> BodyAuthServerConfig<T> {
        let Self { socket_addr, auth_config, server_config, .. } = self;
        BodyAuthServerConfig { socket_addr, auth_config, server_config, rpc_middleware }
    }

    /// Convenience function to start a server in one step.
    pub async fn start(self, module: BodyAuthRpcModule) -> Result<BodyAuthServerHandle, RpcError>
    where
        RpcMiddleware: RethRpcMiddleware,
    {
        let Self { socket_addr, auth_config, server_config, rpc_middleware } = self;

        // Create signature-auth middleware.
        let middleware = tower::ServiceBuilder::new().layer(SignatureAuthLayer::new(auth_config));

        let rpc_middleware = RpcServiceBuilder::default().layer(rpc_middleware);

        // Disable WebSocket — the ops server is HTTP-only. The auth middleware
        // inspects per-request HTTP bodies and would not re-run on individual
        // WebSocket frames after upgrade, bypassing authorization.
        let server = ServerBuilder::new()
            .set_config(server_config.http_only().build())
            .set_http_middleware(middleware)
            .set_rpc_middleware(rpc_middleware)
            .build(socket_addr)
            .await
            .map_err(|err| RpcError::server_error(err, ServerKind::BodyAuth(socket_addr)))?;

        let local_addr = server
            .local_addr()
            .map_err(|err| RpcError::server_error(err, ServerKind::BodyAuth(socket_addr)))?;

        let handle = server.start(module.inner);

        Ok(BodyAuthServerHandle { handle: Some(handle), local_addr })
    }
}

/// Builder type for configuring a [`BodyAuthServerConfig`].
#[derive(Debug)]
pub struct BodyAuthServerConfigBuilder<RpcMiddleware = Identity> {
    socket_addr: Option<SocketAddr>,
    auth_config: SignatureAuthConfig,
    server_config: Option<ServerConfigBuilder>,
    rpc_middleware: RpcMiddleware,
}

impl BodyAuthServerConfigBuilder {
    /// Create a new builder with the given auth configuration.
    pub const fn new(auth_config: SignatureAuthConfig) -> Self {
        Self {
            socket_addr: None,
            auth_config,
            server_config: None,
            rpc_middleware: Identity::new(),
        }
    }
}

impl<RpcMiddleware> BodyAuthServerConfigBuilder<RpcMiddleware> {
    /// Configures the rpc middleware.
    pub fn with_rpc_middleware<T>(self, rpc_middleware: T) -> BodyAuthServerConfigBuilder<T> {
        let Self { socket_addr, auth_config, server_config, .. } = self;
        BodyAuthServerConfigBuilder { socket_addr, auth_config, server_config, rpc_middleware }
    }

    /// Set the socket address for the server.
    pub const fn socket_addr(mut self, socket_addr: SocketAddr) -> Self {
        self.socket_addr = Some(socket_addr);
        self
    }

    /// Set the socket address for the server.
    pub const fn maybe_socket_addr(mut self, socket_addr: Option<SocketAddr>) -> Self {
        self.socket_addr = socket_addr;
        self
    }

    /// Configures the JSON-RPC server.
    ///
    /// Note: this always configures an [`EthSubscriptionIdProvider`]
    /// [`IdProvider`](jsonrpsee::server::IdProvider) for convenience.
    pub fn with_server_config(mut self, config: ServerConfigBuilder) -> Self {
        self.server_config = Some(config.set_id_provider(EthSubscriptionIdProvider::default()));
        self
    }

    /// Build the [`BodyAuthServerConfig`].
    pub fn build(self) -> BodyAuthServerConfig<RpcMiddleware> {
        BodyAuthServerConfig {
            socket_addr: self.socket_addr.unwrap_or_else(|| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_BODY_AUTH_PORT)
            }),
            auth_config: self.auth_config,
            server_config: self.server_config.unwrap_or_else(|| {
                ServerConfig::builder()
                    .max_response_body_size(128 * 1024 * 1024)
                    .max_connections(100)
                    .max_request_body_size(16 * 1024 * 1024)
                    .set_id_provider(EthSubscriptionIdProvider::default())
            }),
            rpc_middleware: self.rpc_middleware,
        }
    }
}

/// Holds installed modules for the ops server.
#[derive(Debug, Clone)]
pub struct BodyAuthRpcModule {
    pub(crate) inner: RpcModule<()>,
}

impl BodyAuthRpcModule {
    /// Create a new `BodyAuthRpcModule` from an `RpcModule`.
    pub const fn new(module: RpcModule<()>) -> Self {
        Self { inner: module }
    }

    /// Create an empty `BodyAuthRpcModule`.
    pub fn empty() -> Self {
        Self { inner: RpcModule::new(()) }
    }

    /// Get a mutable reference to the inner `RpcModule`.
    pub const fn module_mut(&mut self) -> &mut RpcModule<()> {
        &mut self.inner
    }

    /// Merge the given [Methods] into the configured methods.
    ///
    /// Fails if any of the methods in other is present already.
    pub fn merge_methods(
        &mut self,
        other: impl Into<Methods>,
    ) -> Result<bool, RegisterMethodError> {
        self.module_mut().merge(other.into()).map(|_| true)
    }

    /// Removes the method with the given name.
    ///
    /// Returns `true` if the method was found and removed, `false` otherwise.
    pub fn remove_method(&mut self, method_name: &'static str) -> bool {
        self.module_mut().remove_method(method_name).is_some()
    }

    /// Removes the given methods.
    pub fn remove_methods(&mut self, methods: impl IntoIterator<Item = &'static str>) {
        for name in methods {
            self.remove_method(name);
        }
    }

    /// Replace the given [Methods] in the configured methods.
    pub fn replace_methods(
        &mut self,
        other: impl Into<Methods>,
    ) -> Result<bool, RegisterMethodError> {
        let other = other.into();
        self.remove_methods(other.method_names());
        self.merge_methods(other)
    }

    /// Convenience function for starting a server.
    pub async fn start_server<RpcMiddleware: RethRpcMiddleware>(
        self,
        config: BodyAuthServerConfig<RpcMiddleware>,
    ) -> Result<BodyAuthServerHandle, RpcError> {
        config.start(self).await
    }
}

/// A handle to the spawned ops server.
///
/// When this type is dropped or [`BodyAuthServerHandle::stop`] has been called the server will be
/// stopped.
#[derive(Clone, Debug)]
#[must_use = "Server stops if dropped"]
pub struct BodyAuthServerHandle {
    local_addr: SocketAddr,
    handle: Option<jsonrpsee::server::ServerHandle>,
}

impl BodyAuthServerHandle {
    /// Returns the [`SocketAddr`] of the server.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Tell the server to stop without waiting for the server to stop.
    pub fn stop(self) -> Result<(), AlreadyStoppedError> {
        let Some(handle) = self.handle else { return Ok(()) };
        handle.stop()
    }

    /// Returns the url to the http server.
    pub fn http_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}
