use std::sync::Arc;

use alloy_eips::BlockId;
use alloy_primitives::{Address, Bytes, B256};
use alloy_serde::JsonStorageKey;
use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use reth_rpc_api::OpsApiServer;
use reth_rpc_layer::{SignatureScheme, ThresholdConfig};
use reth_storage_api::{BlockIdReader, StateProviderFactory};
use reth_tasks::TaskSpawner;
use tokio::sync::oneshot;

/// `ops` API implementation.
///
/// Provides privileged operations protected by threshold signature authentication.
#[derive(Clone)]
pub struct OpsApi<Provider, S: SignatureScheme> {
    inner: Arc<OpsApiInner<Provider, S>>,
}

struct OpsApiInner<Provider, S: SignatureScheme> {
    /// State provider for storage reads.
    provider: Provider,
    /// Shared threshold config for runtime key management.
    threshold_config: ThresholdConfig<S>,
    /// Task spawner for blocking IO tasks.
    task_spawner: Box<dyn TaskSpawner>,
}

impl<Provider, S: SignatureScheme> OpsApi<Provider, S> {
    /// Creates a new instance of `OpsApi`.
    pub fn new(
        provider: Provider,
        threshold_config: ThresholdConfig<S>,
        task_spawner: Box<dyn TaskSpawner>,
    ) -> Self {
        let inner = Arc::new(OpsApiInner { provider, threshold_config, task_spawner });
        Self { inner }
    }
}

impl<Provider, S> OpsApi<Provider, S>
where
    Provider: StateProviderFactory + BlockIdReader + 'static,
    S: SignatureScheme,
{
    /// Executes a blocking IO task via the managed task spawner.
    async fn spawn_blocking_io<F, R>(&self, f: F) -> Result<R, jsonrpsee::types::ErrorObject<'static>>
    where
        F: FnOnce(Arc<OpsApiInner<Provider, S>>) -> Result<R, jsonrpsee::types::ErrorObject<'static>>
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
impl<Provider, S> OpsApiServer for OpsApi<Provider, S>
where
    Provider: StateProviderFactory + BlockIdReader + 'static,
    S: SignatureScheme,
    S::PublicKey: PartialEq,
{
    async fn get_storage_at(
        &self,
        address: Address,
        index: JsonStorageKey,
        block_number: Option<BlockId>,
    ) -> RpcResult<B256> {
        self.spawn_blocking_io(move |inner| {
            let state = if let Some(block_id) = block_number {
                inner.provider.state_by_block_id(block_id).map_err(|e| internal_err(e.to_string()))?
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

    async fn add_signer_key(&self, public_key: Bytes) -> RpcResult<bool> {
        let key = S::parse_public_key(&public_key)
            .map_err(|e| internal_err(format!("invalid public key: {e}")))?;
        Ok(self.inner.threshold_config.add_key(key))
    }

    async fn remove_signer_key(&self, public_key: Bytes) -> RpcResult<bool> {
        let key = S::parse_public_key(&public_key)
            .map_err(|e| internal_err(format!("invalid public key: {e}")))?;
        Ok(self.inner.threshold_config.remove_key(&key))
    }
}

impl<Provider, S: SignatureScheme> std::fmt::Debug for OpsApi<Provider, S> {
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
