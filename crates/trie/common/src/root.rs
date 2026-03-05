//! Common root computation functions.

// Re-export state root functions from upstream (unchanged).
#[doc(inline)]
pub use alloy_trie::root::{
    state_root, state_root_ref_unhashed, state_root_unhashed, state_root_unsorted,
};

// Re-export FlaggedStorage-aware storage root functions from seismic-alloy-trie.
#[doc(inline)]
pub use seismic_alloy_trie::{storage_root, storage_root_unhashed, storage_root_unsorted};
