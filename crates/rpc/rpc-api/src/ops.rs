use alloy_eips::BlockId;
use alloy_primitives::{Address, Bytes, B256};
use alloy_serde::JsonStorageKey;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Ops namespace rpc interface for privileged operations protected by threshold signature auth.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "ops"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "ops"))]
pub trait OpsApi {
    /// Returns the value from a storage position at a given address, bypassing the storage API
    /// gate. This endpoint is only available on the threshold-auth server.
    #[method(name = "getStorageAt")]
    async fn get_storage_at(
        &self,
        address: Address,
        index: JsonStorageKey,
        block_number: Option<BlockId>,
    ) -> RpcResult<B256>;

    /// Adds a public key to the set of allowed signers.
    /// The key is hex-encoded.
    #[method(name = "addSignerKey")]
    async fn add_signer_key(&self, public_key: Bytes) -> RpcResult<bool>;

    /// Removes a public key from the set of allowed signers.
    /// The key is hex-encoded.
    #[method(name = "removeSignerKey")]
    async fn remove_signer_key(&self, public_key: Bytes) -> RpcResult<bool>;
}
