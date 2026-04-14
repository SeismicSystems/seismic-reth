//! Seismic-specific pool maintenance hook that augments native balances with
//! USDC predeploy balances.

use reth_execution_types::ChangedAccount;
use reth_provider::StateProvider;
use reth_transaction_pool::maintain::ChangedAccountsHook;
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
}
