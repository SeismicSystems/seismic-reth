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
/// - `ops_whitelistKey`: governance-only, adds an address to the whitelist until an absolute expiry
/// - `ops_getStorageAt`: whitelist-only, reads storage
#[derive(Clone)]
pub struct OpsApi<Provider> {
    inner: Arc<OpsApiInner<Provider>>,
}

struct OpsApiInner<Provider> {
    /// State provider for storage reads.
    provider: Provider,
    /// Task spawner for blocking IO tasks.
    task_spawner: Box<dyn TaskSpawner>,
    /// Shared whitelist for temporarily authorized addresses.
    whitelist: Whitelist,
    /// Shared in-memory next expected nonce per whitelisted signer.
    nonces: Arc<RwLock<HashMap<Address, u64>>>,
}

impl<Provider> OpsApi<Provider> {
    /// Creates a new instance of `OpsApi`.
    pub fn new(
        provider: Provider,
        task_spawner: Box<dyn TaskSpawner>,
        whitelist: Whitelist,
        nonces: Arc<RwLock<HashMap<Address, u64>>>,
    ) -> Self {
        let inner = Arc::new(OpsApiInner { provider, task_spawner, whitelist, nonces });
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

    async fn whitelist_key(&self, address: Address, expires_at: u64) -> RpcResult<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| internal_err("system clock before unix epoch".to_string()))?
            .as_secs();
        if expires_at <= now {
            return Err(invalid_params_err("Expiry timestamp must be in the future".to_string()));
        }

        self.inner.whitelist.add(address, expires_at);
        Ok(true)
    }

    async fn revoke_key(&self, address: Address) -> RpcResult<bool> {
        Ok(self.inner.whitelist.remove(&address))
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

fn invalid_params_err(msg: String) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        msg,
        None::<()>,
    )
}
