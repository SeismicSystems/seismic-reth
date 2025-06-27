use alloy_primitives::{B256, U256};
use revm_state::FlaggedStorage;

/// Account storage entry.
///
/// `key` is the subkey when used as a value in the `StorageChangeSets` table.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct StorageEntry {
    /// Storage key.
    pub key: B256,
    /// Value on storage key.
    pub value: U256,
    /// Indicates whether the value is private
    pub is_private: bool,
}

impl StorageEntry {
    /// Create a new `StorageEntry` with given key and value.
    pub const fn new(key: B256, value: U256, is_private: bool) -> Self {
        Self { key, value, is_private }
    }

    /// Convert the storage entry to a flagged storage entry.
    pub const fn to_flagged_storage(self) -> FlaggedStorage {
        FlaggedStorage { value: self.value, is_private: self.is_private }
    }
}

impl From<(B256, U256, bool)> for StorageEntry {
    fn from((key, value, is_private): (B256, U256, bool)) -> Self {
        Self { key, value, is_private }
    }
}

impl From<(B256, (U256, bool))> for StorageEntry {
    fn from((key, (value, is_private)): (B256, (U256, bool))) -> Self {
        Self { key, value, is_private }
    }
}

impl From<StorageEntry> for FlaggedStorage {
    fn from(entry: StorageEntry) -> Self {
        Self { value: entry.value, is_private: entry.is_private }
    }
}

// NOTE: Removing reth_codec and manually encode subkey
// and compress second part of the value. If we have compression
// over whole value (Even SubKey) that would mess up fetching of values with seek_by_key_subkey
#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for StorageEntry {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        // for now put full bytes and later compress it.
        buf.put_slice(&self.key[..]);
        buf.put_u8(self.is_private as u8);
        self.value.to_compact(buf) + 32 + 1
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let key = B256::from_slice(&buf[..32]);
        let is_private = buf[32] != 0;
        let (value, out) = U256::from_compact(&buf[33..], len - 33);
        (Self { key, value, is_private }, out)
    }
}
