//! Seismic transaction types

pub mod error;
pub mod signed;
pub mod tx_type;

/// Defines how recent [`recent_block_hash`] must be for a signed seismic transaction to count as
/// fresh.
pub const SEISMIC_TX_RECENT_BLOCK_LOOKBACK: u64 = 1000;
