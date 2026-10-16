//! Seismic purpose-key rotation: registry protocol constants plus re-exports of the
//! epoch-keyed keyring.
//!
//! Purpose keys (the tx-io keypair and the RNG ikm) are derived per **epoch** by the
//! key custodian. Epochs advance via on-chain rotation announcements (see
//! `docs/design/purpose-key-rotation.md`); the epoch active for a block is a
//! deterministic function of chain state, so every consumer selects keys through the
//! [`PurposeKeyring`] rather than holding a single static key bundle.
//!
//! Keyring, canonical-view and schedule types live in `alloy-seismic-evm` next to
//! [`PurposeKeys`](alloy_seismic_evm::PurposeKeys). This crate re-exports them and
//! the shared [`registry`] decoder for the canonical watcher and RPC/pool policy.
//! Block execution selects from its own parent state, not the canonical view.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod registry;

pub use alloy_seismic_evm::{
    CanonicalRotationView, EpochKeyConflict, MissingEpochKeys, PurposeKeyring, RotationEntry,
    RotationSchedule, ScheduleError,
};

// Keyring, schedule and registry-decoding tests live with their implementations
// in `alloy-seismic-evm`.
