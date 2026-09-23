use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use alloy_eips::BlockId;
use alloy_primitives::{Address, B256};
use alloy_serde::JsonStorageKey;
use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use reth_rpc_api::OpsApiServer;
use reth_rpc_layer::Whitelist;
use reth_storage_api::{BlockIdReader, StateProviderFactory};
use reth_tasks::TaskSpawner;
use tokio::sync::oneshot;

/// `ops` API implementation.
///
/// Provides privileged storage read operations protected by signature authentication.
/// - `ops_getStorageAt`: whitelist-only, reads storage
/// - `ops_getNonce`: whitelist-only, returns the next expected nonce
/// - `ops_getValidatorId`: unauthenticated, returns the per-process random id
/// - `ops_getAdminNonce`: unauthenticated, returns the last consumed admin nonce
#[derive(Clone)]
pub struct OpsApi<Provider> {
    inner: Arc<OpsApiInner<Provider>>,
}

struct OpsApiInner<Provider> {
    /// State provider for storage reads.
    provider: Provider,
    /// Task spawner for blocking IO tasks.
    task_spawner: Box<dyn TaskSpawner>,
    /// Shared in-memory next expected nonce per whitelisted signer (HTTP auth).
    nonces: Arc<RwLock<HashMap<Address, u64>>>,
    /// Shared whitelist; also carries the validator id and admin nonce used by
    /// the sentinel-tx replay protection.
    whitelist: Whitelist,
}

impl<Provider> OpsApi<Provider> {
    /// Creates a new instance of `OpsApi`.
    pub fn new(
        provider: Provider,
        task_spawner: Box<dyn TaskSpawner>,
        nonces: Arc<RwLock<HashMap<Address, u64>>>,
        whitelist: Whitelist,
    ) -> Self {
        let inner = Arc::new(OpsApiInner { provider, task_spawner, nonces, whitelist });
        Self { inner }
    }
}

impl<Provider> OpsApi<Provider>
where
    Provider: StateProviderFactory + BlockIdReader + 'static,
{
    /// Executes a blocking IO task via the managed task spawner.
    async fn spawn_blocking_io<F, R>(
        &self,
        f: F,
    ) -> Result<R, jsonrpsee::types::ErrorObject<'static>>
    where
        F: FnOnce(Arc<OpsApiInner<Provider>>) -> Result<R, jsonrpsee::types::ErrorObject<'static>>
            + Send
            + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let inner = self.inner.clone();
        self.inner.task_spawner.spawn_blocking(Box::pin(async move {
            let res = f(inner);
            let _ = tx.send(res);
        }));
        rx.await.map_err(|_| internal_err("blocking task cancelled".to_string()))?
    }
}

#[async_trait]
impl<Provider> OpsApiServer for OpsApi<Provider>
where
    Provider: StateProviderFactory + BlockIdReader + 'static,
{
    async fn get_storage_at(
        &self,
        address: Address,
        index: JsonStorageKey,
        block_number: Option<BlockId>,
    ) -> RpcResult<B256> {
        self.spawn_blocking_io(move |inner| {
            let state = if let Some(block_id) = block_number {
                inner
                    .provider
                    .state_by_block_id(block_id)
                    .map_err(|e| internal_err(e.to_string()))?
            } else {
                inner.provider.latest().map_err(|e| internal_err(e.to_string()))?
            };

            let value = state
                .storage(address, index.as_b256())
                .map_err(|e| internal_err(e.to_string()))?
                .unwrap_or_default();

            Ok(B256::new(value.value.to_be_bytes()))
        })
        .await
    }

    async fn get_nonce(&self, address: Address) -> RpcResult<u64> {
        self.spawn_blocking_io(move |inner| {
            let nonce = inner
                .nonces
                .read()
                .map_err(|_| internal_err("nonce lock poisoned".to_string()))?
                .get(&address)
                .copied()
                .unwrap_or(0);
            Ok(nonce)
        })
        .await
    }

    async fn get_validator_id(&self) -> RpcResult<B256> {
        Ok(self.inner.whitelist.validator_id())
    }

    async fn get_admin_nonce(&self) -> RpcResult<u64> {
        Ok(self.inner.whitelist.admin_nonce())
    }
}

impl<Provider> std::fmt::Debug for OpsApi<Provider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsApi").finish_non_exhaustive()
    }
}

fn internal_err(msg: String) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        msg,
        None::<()>,
    )
}
