//! Seismic transaction types

use alloy_consensus::{EthereumTxEnvelope, TxEip4844WithSidecar};
use alloy_eips::eip7594::BlobTransactionSidecarVariant;
use reth_primitives_traits::Extended;
use seismic_alloy_consensus::SeismicTxEnvelope;

pub mod error;
pub mod signed;
pub mod tx_type;

/// Network representation for transactions accepted by the Seismic transaction pool.
///
/// Ethereum transaction types use the standard pooled envelope so EIP-4844 transactions retain
/// their sidecars. The non-overlapping `Other` branch is reserved for Seismic transactions.
pub type SeismicPooledTransactionVariant = Extended<
    EthereumTxEnvelope<TxEip4844WithSidecar<BlobTransactionSidecarVariant>>,
    SeismicTxEnvelope,
>;

/// Defines how recent [`recent_block_hash`] must be for a signed seismic transaction to count as
/// fresh.
pub const SEISMIC_TX_RECENT_BLOCK_LOOKBACK: u64 = 100;
