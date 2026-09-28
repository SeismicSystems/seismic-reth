//! JSON-RPC error codes for Seismic-specific errors.
//!
//! Standard JSON-RPC reserves -32700 to -32600 (parse/request errors) and
//! -32099 to -32000 (server errors). Seismic-specific codes use the
//! application-defined range starting at -39000.

/// Calldata decryption failed (ECDH / AES-GCM error).
pub const DECRYPTION_ERROR: i32 = -39001;
/// Output re-encryption failed.
pub const ENCRYPTION_ERROR: i32 = -39002;
/// Transaction `expires_at_block` is in the past.
pub const TRANSACTION_EXPIRED: i32 = -39003;
/// `recent_block_hash` not found in the canonical lookback window.
pub const RECENT_BLOCK_HASH_NOT_FOUND: i32 = -39004;
