//! Epoch-keyed purpose-key management for Seismic nodes.
//!
//! Purpose keys (the tx-io keypair and the RNG ikm) are derived per **epoch** by the
//! key custodian. Epochs advance via on-chain rotation announcements (see
//! `docs/design/purpose-key-rotation.md`); the epoch active for a block is a
//! deterministic function of chain state, so every consumer selects keys through the
//! [`PurposeKeyring`] rather than holding a single static key bundle.
//!
//! This crate is deliberately small and sits below the txpool, RPC, and node crates:
//! - [`RotationSchedule`] / [`RotationEntry`]: the validated, append-only rotation history (no key
//!   material).
//! - [`PurposeKeyring`]: the schedule plus the per-epoch key material, behind shared swappable
//!   state.
//! - [`registry`]: the `KeyRotationRegistry` predeploy's protocol constants and storage decoding.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod keyring;
pub mod registry;
mod schedule;

pub use keyring::{EpochKeyConflict, MissingEpochKeys, PurposeKeyring};
pub use schedule::{RotationEntry, RotationSchedule, ScheduleError};
