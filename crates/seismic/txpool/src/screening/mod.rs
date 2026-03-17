//! Address screening via ECSD (Ethereum Compliance Screening Daemon) sidecar.
//!
//! Provides optional transaction screening at pool admission as an operator policy layer.
//! Screens transaction-level addresses (sender, recipient, EIP-7702, access list) and
//! addresses embedded in ERC-20/ERC-721/ERC-1155 token transfer calldata.

pub(crate) mod calldata;
mod client;
mod metrics;
pub mod proto;
mod validator;

pub use calldata::{extract_addresses, extract_calldata_addresses};
pub use client::{ScreeningClient, ScreeningClientBuilder, ScreeningError, ScreeningFailMode};
pub use validator::ScreeningTransactionValidator;
