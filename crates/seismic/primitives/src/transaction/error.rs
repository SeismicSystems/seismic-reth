//! Seismic transaction error types

use alloy_primitives::B256;

/// Errors specific to seismic transactions
#[derive(Debug, Clone, Eq, PartialEq, derive_more::Display)]
pub enum SeismicTxError {
    /// The recent_block_hash was not found in the last N blocks
    #[display("recent_block_hash {hash} not found in the last {lookback} blocks")]
    RecentBlockHashNotFound {
        /// The recent_block_hash that was provided
        hash: B256,
        /// Number of blocks searched
        lookback: u64,
    },
    /// The transaction has expired based on expires_at_block
    #[display(
        "transaction expired: current block {current_block} > expires_at_block {expires_at_block}"
    )]
    TransactionExpired {
        /// Current block number
        current_block: u64,
        /// The block number at which the transaction expires
        expires_at_block: u64,
    },
    /// A write transaction (non-contract creation) cannot have signed_read = true
    #[display("write transactions cannot have signed_read set to true")]
    InvalidSignedReadForWrite,
    /// Failed to decrypt calldata of seismic tx
    #[display("failed to decrypt seismic transaction")]
    FailedToDecrypt,
}
