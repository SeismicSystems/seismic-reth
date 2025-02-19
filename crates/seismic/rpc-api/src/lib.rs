//! This crate provides the seismic rpc api implementation.

/// Error types for the seismic rpc api
pub mod error;
/// The seismic rpc api implementation
pub mod rpc;
/// Utils for testing the seismic rpc api
#[cfg(test)]
pub mod utils;
