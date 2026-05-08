//! Seismic overrides for the `debug_` RPC namespace.
//!
//! `debug_executionWitness` and `debug_executionWitnessByBlockHash` return the preimages
//! of every storage trie leaf the block touched, including shielded slot values.
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::B256;
use alloy_rpc_types_debug::ExecutionWitness;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    types::{error::ErrorObject, ErrorObjectOwned},
};

/// Seismic override of the `debug_` RPC namespace.
///
/// Only includes the methods seismic needs to override; merging into the module container
/// replaces just these handlers and leaves the rest of `debug_*` intact.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "debug"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "debug"))]
pub trait DebugWitnessOverride {
    /// Disabled — see module docs.
    #[method(name = "executionWitness")]
    async fn debug_execution_witness(&self, block: BlockNumberOrTag)
        -> RpcResult<ExecutionWitness>;

    /// Disabled — see module docs.
    #[method(name = "executionWitnessByBlockHash")]
    async fn debug_execution_witness_by_block_hash(
        &self,
        hash: B256,
    ) -> RpcResult<ExecutionWitness>;
}

/// Implementation that rejects every call with a fixed error.
#[derive(Debug, Clone, Copy)]
pub struct DebugWitnessDisabled;

#[async_trait]
impl DebugWitnessOverrideServer for DebugWitnessDisabled {
    async fn debug_execution_witness(
        &self,
        _block: BlockNumberOrTag,
    ) -> RpcResult<ExecutionWitness> {
        Err(witness_disabled_error())
    }

    async fn debug_execution_witness_by_block_hash(
        &self,
        _hash: B256,
    ) -> RpcResult<ExecutionWitness> {
        Err(witness_disabled_error())
    }
}

fn witness_disabled_error() -> ErrorObjectOwned {
    ErrorObject::owned(-32000, "debug_executionWitness is disabled", None::<String>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execution_witness_returns_disabled_error() {
        let api = DebugWitnessDisabled;
        let err = api
            .debug_execution_witness(BlockNumberOrTag::Latest)
            .await
            .expect_err("expected disabled error");
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), "debug_executionWitness is disabled");
    }

    #[tokio::test]
    async fn execution_witness_by_hash_returns_disabled_error() {
        let api = DebugWitnessDisabled;
        let err = api
            .debug_execution_witness_by_block_hash(B256::ZERO)
            .await
            .expect_err("expected disabled error");
        assert_eq!(err.code(), -32000);
        assert_eq!(err.message(), "debug_executionWitness is disabled");
    }
}
