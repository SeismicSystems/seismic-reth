//! Named JSON-RPC error codes for Seismic-specific `eth_` errors.
//!
//! These previously all shared the generic server-error code `-32000`,
//! which made it impossible for clients to distinguish one Seismic error
//! from another without parsing the (unstable) message string. Each error
//! now gets its own code in the reserved-for-implementation-defined-errors
//! range (JSON-RPC 2.0 reserves `-32000` to `-32099` for server errors).

/// Seismic-specific JSON-RPC error codes.
///
/// Client SDKs can match on these to handle each error case programmatically,
/// e.g. `if err.code == seismic_error_codes::DECRYPTION_ERROR`.
pub mod seismic_error_codes {
    /// Returned when decrypting a Seismic shielded payload fails.
    pub const DECRYPTION_ERROR: i32 = -39001;
    /// Returned when encrypting a Seismic shielded payload fails.
    pub const ENCRYPTION_ERROR: i32 = -39002;
    /// Returned when a signed read's `expires_at_block` has already passed.
    pub const TRANSACTION_EXPIRED: i32 = -39003;
    /// Returned when a signed read's `recent_block_hash` is not found among
    /// the last `SEISMIC_TX_RECENT_BLOCK_LOOKBACK` canonical blocks.
    pub const RECENT_BLOCK_HASH_NOT_FOUND: i32 = -39004;
}
