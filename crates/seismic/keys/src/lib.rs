//! Seismic purpose-key rotation: registry protocol constants plus re-exports of the
//! epoch-keyed keyring.
//!
//! Purpose keys (the tx-io keypair and the RNG ikm) are derived per **epoch** by the
//! key custodian. Epochs advance via on-chain rotation announcements (see
//! `docs/design/purpose-key-rotation.md`); the epoch active for a block is a
//! deterministic function of chain state, so every consumer selects keys through the
//! [`PurposeKeyring`] rather than holding a single static key bundle.
//!
//! The keyring and schedule types live in `alloy-seismic-evm` (next to
//! [`PurposeKeys`](alloy_seismic_evm::PurposeKeys), so the EVM factories can select
//! keys per block) and are re-exported here; this crate owns what is
//! seismic-reth-specific:
//! - [`registry`]: the `KeyRotationRegistry` predeploy's protocol constants and storage decoding,
//!   which the rotation watcher and boot reconciliation read the schedule with.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod registry;

pub use alloy_seismic_evm::{
    EpochKeyConflict, MissingEpochKeys, PurposeKeyring, RotationEntry, RotationSchedule,
    ScheduleError,
};

// The keyring/schedule unit tests live with the types in `alloy-seismic-evm`; this
// crate's tests cover the registry decoding in `registry`.
