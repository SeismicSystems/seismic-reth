use crate::{HashBuilder, Nibbles};
use alloy_primitives::{Address, B256};
use alloy_rlp::encode_fixed_size;
use reth_primitives_traits::Account;
use reth_trie_common::triehash::KeccakHasher;

/// Re-export of [triehash].
pub use triehash;

/// Compute the state root of a given set of accounts using [`triehash::sec_trie_root`].
pub fn state_root<I, S>(accounts: I) -> B256
where
    I: IntoIterator<Item = (Address, (Account, S))>,
    S: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>,
{
    let encoded_accounts = accounts.into_iter().map(|(address, (account, storage))| {
        let storage_root = storage_root(storage);
        let account = account.into_trie_account(storage_root);
        (address, alloy_rlp::encode(account))
    });
    triehash::sec_trie_root::<KeccakHasher, _, _, _>(encoded_accounts)
}

/// Compute the storage root for a given account using [`triehash::sec_trie_root`].
pub fn storage_root<I: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>>(
    storage: I,
) -> B256 {
    let encoded_storage = storage.into_iter().map(|(k, v)| (k, encode_fixed_size(&v)));
    triehash::sec_trie_root::<KeccakHasher, _, _, _>(encoded_storage)
}

/// Compute the state root of a given set of accounts with prehashed keys using
/// [`triehash::trie_root`].
pub fn state_root_prehashed<I, S>(accounts: I) -> B256
where
    I: IntoIterator<Item = (B256, (Account, S))>,
    S: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>,
{
    let encoded_accounts = accounts.into_iter().map(|(address, (account, storage))| {
        let storage_root = storage_root_prehashed(storage);
        let account = account.into_trie_account(storage_root);
        (address, alloy_rlp::encode(account))
    });

    triehash::trie_root::<KeccakHasher, _, _, _>(encoded_accounts)
}

/// Compute the storage root for a given account with prehashed slots using [`triehash::trie_root`].
pub fn storage_root_prehashed<I: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>>(
    storage: I,
) -> B256 {
    let encoded_storage = storage.into_iter().map(|(k, v)| (k, encode_fixed_size(&v)));
    triehash::trie_root::<KeccakHasher, _, _, _>(encoded_storage)
}

/// Compute the state root of a given set of accounts using privacy-aware HashBuilder.
/// This function respects the privacy flags in FlaggedStorage values and hashes the keys.
pub fn state_root_privacy_aware<I, S>(accounts: I) -> B256
where
    I: IntoIterator<Item = (Address, (Account, S))>,
    S: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>,
{
    let mut hash_builder = HashBuilder::default();

    // Collect and sort account entries by hashed address for consistent ordering
    let mut account_entries: Vec<_> = accounts
        .into_iter()
        .map(|(address, (account, storage))| {
            let storage_root = storage_root_privacy_aware(storage);
            let account = account.into_trie_account(storage_root);
            (alloy_primitives::keccak256(address), account)
        })
        .collect();
    account_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Add each account entry to the hash builder
    // Note: Account privacy is determined by whether it has private storage
    for (hashed_address, account) in account_entries {
        let nibbles = Nibbles::unpack(hashed_address);
        let encoded_account = alloy_rlp::encode(account);
        hash_builder.add_leaf(nibbles, &encoded_account);
    }

    hash_builder.root()
}

/// Compute the storage root for a given account using privacy-aware HashBuilder.
/// This function respects the privacy flags in FlaggedStorage values and hashes the keys.
pub fn storage_root_privacy_aware<
    I: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>,
>(
    storage: I,
) -> B256 {
    let mut hash_builder = HashBuilder::default();

    // Collect and sort storage entries by hashed key for consistent ordering
    let mut storage_entries: Vec<_> =
        storage.into_iter().map(|(k, v)| (alloy_primitives::keccak256(k), v)).collect();
    storage_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Add each storage entry to the hash builder with privacy awareness
    for (hashed_key, flagged_storage) in storage_entries {
        let nibbles = Nibbles::unpack(hashed_key);
        let encoded_value = encode_fixed_size(&flagged_storage);
        hash_builder.add_leaf(nibbles, &encoded_value);
    }

    hash_builder.root()
}

/// Compute the storage root for a given account with prehashed slots using privacy-aware
/// HashBuilder. This function respects the privacy flags in FlaggedStorage values, unlike the
/// standard version above.
pub fn storage_root_prehashed_privacy_aware<
    I: IntoIterator<Item = (B256, alloy_primitives::FlaggedStorage)>,
>(
    storage: I,
) -> B256 {
    let mut hash_builder = HashBuilder::default();

    // Collect and sort storage entries by key for consistent ordering
    let mut storage_entries: Vec<_> = storage.into_iter().collect();
    storage_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Add each storage entry to the hash builder with privacy awareness
    for (key, flagged_storage) in storage_entries {
        let nibbles = Nibbles::unpack(key);
        let encoded_value = encode_fixed_size(&flagged_storage);
        hash_builder.add_leaf(nibbles, &encoded_value);
    }

    hash_builder.root()
}
