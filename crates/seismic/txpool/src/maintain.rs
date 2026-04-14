//! Seismic-specific pool maintenance hook that augments native balances with
//! USDC predeploy balances.

use alloy_primitives::{Address, B256};
use reth_execution_types::{ChangedAccount, ExecutionOutcome};
use reth_provider::StateProvider;
use reth_transaction_pool::maintain::ChangedAccountsHook;
use std::collections::HashSet;
use tracing::debug;

/// A [`ChangedAccountsHook`] that reads each sender's USDC predeploy balance
/// and sets `balance = max(native, usdc_scaled)` so the pool can make accurate
/// demotion decisions for accounts paying gas in USDC.
///
/// The hook uses the [`StateProvider`] passed by the maintenance loop rather
/// than opening its own snapshot, so the USDC balance is always read from the
/// same block as the native balance and nonce.
#[derive(Debug, Default)]
pub struct SeismicBalanceHook;

impl ChangedAccountsHook for SeismicBalanceHook {
    fn transform(&self, state: &dyn StateProvider, accounts: &mut Vec<ChangedAccount>) {
        for acc in accounts.iter_mut() {
            let usdc = crate::usdc::read_usdc_balance(state, &acc.address);
            let new_balance = std::cmp::max(acc.balance, usdc);
            if new_balance != acc.balance {
                debug!(
                    target: "seismic::txpool",
                    address = %acc.address,
                    native_balance = %acc.balance,
                    usdc_scaled_balance = %usdc,
                    effective_balance = %new_balance,
                    "augmenting changed account balance with USDC"
                );
                acc.balance = new_balance;
            }
        }
    }

    fn extend_reload_queued_senders<R>(
        &self,
        queued_senders: &HashSet<Address>,
        old: Option<&ExecutionOutcome<R>>,
        new: &ExecutionOutcome<R>,
        dirty_addresses: &mut HashSet<Address>,
    ) {
        dirty_addresses.extend(queued_senders_with_changed_usdc_slots(queued_senders, old, new));
    }
}

fn queued_senders_with_changed_usdc_slots<'a, R>(
    queued_senders: &'a HashSet<Address>,
    old: Option<&ExecutionOutcome<R>>,
    new: &ExecutionOutcome<R>,
) -> impl Iterator<Item = Address> + 'a {
    let changed_slots = changed_usdc_storage_slots(new)
        .into_iter()
        .chain(old.into_iter().flat_map(changed_usdc_storage_slots))
        .collect::<HashSet<_>>();

    queued_senders.iter().copied().filter(move |address| {
        changed_slots.contains(&crate::usdc::usdc_balance_storage_key(address))
    })
}

fn changed_usdc_storage_slots<R>(state: &ExecutionOutcome<R>) -> impl Iterator<Item = B256> + '_ {
    state
        .bundle_accounts_iter()
        .filter_map(|(address, account)| (address == crate::usdc::USDC_CONTRACT).then_some(account))
        .flat_map(|account| {
            account.storage.iter().filter_map(|(slot, value)| {
                value.is_changed().then(|| B256::from(slot.to_be_bytes::<32>()))
            })
        })
}
