use alloy_eips::BlockId;
use alloy_primitives::{Address, B256};
use alloy_serde::JsonStorageKey;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Ops namespace rpc interface for privileged operations protected by signature auth.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "ops"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "ops"))]
pub trait OpsApi {
    /// Returns the value from a storage position at a given address, bypassing the storage API
    /// gate. Requires a whitelisted key.
    ///
    /// This endpoint uses incrementing nonce protection. The nonce must match the current expected
    /// nonce for the authenticated signer.
    #[method(name = "getStorageAt")]
    async fn get_storage_at(
        &self,
        address: Address,
        index: JsonStorageKey,
        block_number: Option<BlockId>,
    ) -> RpcResult<B256>;

    /// Returns the next expected nonce for a whitelisted key.
    ///
    /// The request must be authenticated by the same whitelisted address passed in `address`.
    #[method(name = "getNonce")]
    async fn get_nonce(&self, address: Address) -> RpcResult<u64>;

    /// Adds an address to the whitelist with a TTL in seconds.
    /// Only the admin key (from the contract storage slot) can call this.
    /// Once whitelisted, the address can authenticate `ops_getStorageAt` until the TTL expires.
    #[method(name = "whitelistKey")]
    async fn whitelist_key(&self, address: Address, ttl_seconds: u64) -> RpcResult<bool>;

    /// Removes an address from the whitelist.
    /// Only the admin key (from the contract storage slot) can call this.
    /// Returns `true` if the address was whitelisted, `false` if it was not found.
    #[method(name = "revokeKey")]
    async fn revoke_key(&self, address: Address) -> RpcResult<bool>;
}
