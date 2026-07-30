//! Seismic transaction error types

use alloy_primitives::B256;

/// Errors specific to seismic transactions
#[derive(Debug, Clone, Eq, PartialEq, derive_more::Display)]
pub enum SeismicTxError {
    /// The `recent_block_hash` was not found in the last `lookback` blocks
    #[display("recent_block_hash {hash} not found in the last {lookback} blocks")]
    RecentBlockHashNotFound {
        /// The `recent_block_hash` that was provided
        hash: B256,
        /// Number of blocks searched
        lookback: u64,
    },
    /// The transaction has expired based on `expires_at_block`
    #[display(
        "transaction expired: current block {current_block} > expires_at_block {expires_at_block}"
    )]
    TransactionExpired {
        /// Current block number
        current_block: u64,
        /// The block number at which the transaction expires
        expires_at_block: u64,
    },
    /// The transaction's expiry crosses a pending key-rotation activation boundary
    /// (`docs/design/purpose-key-rotation.md` §6): it could otherwise sit in the pool
    /// past the rotation, encrypted to a key the network no longer uses.
    #[display(
        "transaction expiry {expires_at_block} crosses the key-rotation boundary at block {activation_block}; shorten the expiry or re-encrypt to the new network key after activation"
    )]
    ExpiryCrossesRotation {
        /// The transaction's `expires_at_block`
        expires_at_block: u64,
        /// The pending rotation's activation block
        activation_block: u64,
    },
    /// Failed to decrypt calldata of seismic tx
    #[display("failed to decrypt seismic transaction")]
    FailedToDecrypt,
}
