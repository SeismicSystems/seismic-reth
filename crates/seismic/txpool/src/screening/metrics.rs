//! Runtime metrics for address screening.

use reth_metrics::{
    metrics::{Counter, Histogram},
    Metrics,
};

/// Metrics for the address screening subsystem.
///
/// Emitted by [`ScreeningTransactionValidator`](super::ScreeningTransactionValidator) and
/// available via the Prometheus `/metrics` endpoint when the node is running.
#[derive(Metrics)]
#[metrics(scope = "transaction_pool.screening")]
pub(super) struct ScreeningMetrics {
    /// Time spent on the gRPC round-trip to ECSD (seconds).
    pub(crate) screening_request_duration: Histogram,
    /// Time spent extracting addresses from transaction calldata (seconds).
    pub(crate) address_extraction_duration: Histogram,
    /// Number of addresses sent per screening request.
    pub(crate) addresses_per_request: Histogram,
    /// Total transactions screened.
    pub(crate) screened_transactions: Counter,
    /// Transactions rejected due to flagged addresses.
    pub(crate) flagged_transactions: Counter,
    /// Screening errors (sidecar unreachable, timeout, etc.).
    pub(crate) screening_errors: Counter,
}
