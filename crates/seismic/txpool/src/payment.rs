//! Registry-backed pool admission using one provider snapshot.
//!
//! Exact single-asset selection is distinct from the approximate sender-wide
//! balance used by the pool for promotion. Neither result is a public balance RPC.

use alloy_consensus::Transaction;
use alloy_primitives::{Address, FlaggedStorage, U256};
use reth_provider::{ProviderError, StateProvider};
use revm::context::result::InvalidTransaction;
use seismic_revm::gas_token_registry::RegistryStorage;

/// Adapt provider storage to the shared decoder without losing privacy flags or errors.
pub(crate) struct ProviderRegistryStorage<'a>(pub(crate) &'a dyn StateProvider);

impl RegistryStorage for ProviderRegistryStorage<'_> {
    type Error = ProviderError;

    fn read_storage(&mut self, address: Address, key: U256) -> Result<FlaggedStorage, Self::Error> {
        self.0.storage(address, key.to_be_bytes::<32>().into()).map(Option::unwrap_or_default)
    }
}

/// Maximum gas fee in wei, including blobs, without subtracting value from the
/// pool's saturated cost cache. Exact affordability must not use that approximation.
pub(crate) fn maximum_gas_cost(tx: &impl Transaction) -> Result<U256, InvalidTransaction> {
    let gas = U256::from(tx.gas_limit()) * U256::from(tx.max_fee_per_gas());
    let blob = U256::from(tx.blob_gas_used().unwrap_or_default()) *
        U256::from(tx.max_fee_per_blob_gas().unwrap_or_default());
    gas.checked_add(blob).ok_or(InvalidTransaction::OverflowPaymentInTransaction)
}
