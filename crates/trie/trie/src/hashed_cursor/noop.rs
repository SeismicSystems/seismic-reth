use super::{HashedCursor, HashedCursorFactory, HashedStorageCursor};
use alloy_primitives::B256;
use reth_primitives_traits::Account;
use reth_storage_errors::db::DatabaseError;
use revm_state::FlaggedStorage;

/// Noop hashed cursor factory.
#[derive(Clone, Default, Debug)]
#[non_exhaustive]
pub struct NoopHashedCursorFactory;

impl HashedCursorFactory for NoopHashedCursorFactory {
    type AccountCursor = NoopHashedAccountCursor;
    type StorageCursor = NoopHashedStorageCursor;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, DatabaseError> {
        Ok(NoopHashedAccountCursor::default())
    }

    fn hashed_storage_cursor(
        &self,
        _hashed_address: B256,
    ) -> Result<Self::StorageCursor, DatabaseError> {
        Ok(NoopHashedStorageCursor::default())
    }
}

/// Noop account hashed cursor.
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct NoopHashedAccountCursor;

impl HashedCursor for NoopHashedAccountCursor {
    type Value = Account;

    fn seek(&mut self, _key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(None)
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(None)
    }
}

/// Noop account hashed cursor.
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct NoopHashedStorageCursor;

impl HashedCursor for NoopHashedStorageCursor {
    type Value = FlaggedStorage;

    fn seek(&mut self, _key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(None)
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(None)
    }
}

impl HashedStorageCursor for NoopHashedStorageCursor {
    fn is_storage_empty(&mut self) -> Result<bool, DatabaseError> {
        Ok(true)
    }
}
