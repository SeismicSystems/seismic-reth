//! Shared harness infrastructure for fuzzing seismic-reth.
//!
//! Provides mock purpose keys, pre-seeded state databases, EVM factory
//! construction, and structured transaction generators for fuzz targets.

pub mod mock_evm;
pub mod mock_keys;
pub mod mock_state;
pub mod triage;
pub mod tx_gen;
