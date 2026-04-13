//! Seismic-specific pool maintenance hook that augments native balances with
//! USDC predeploy balances.

use reth_execution_types::ChangedAccount;
use reth_provider::StateProviderFactory;
use reth_transaction_pool::maintain::ChangedAccountsHook;
use tracing::{debug, warn};

/// A [`ChangedAccountsHook`] that reads each sender's USDC predeploy balance
/// and sets `balance = max(native, usdc_scaled)` so the pool can make accurate
/// demotion decisions for accounts paying gas in USDC.
#[derive(Debug)]
pub struct SeismicBalanceHook<C> {
    client: C,
}

impl<C> SeismicBalanceHook<C> {
    /// Creates a new hook backed by the given state provider factory.
    pub const fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C> ChangedAccountsHook for SeismicBalanceHook<C>
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    fn transform(&self, accounts: &mut Vec<ChangedAccount>) {
        let state = match self.client.latest() {
            Ok(s) => s,
            Err(err) => {
                warn!(target: "seismic::txpool", %err, "failed to get latest state for USDC balance augmentation");
                return;
            }
        };

        for acc in accounts.iter_mut() {
            let usdc = crate::usdc::read_usdc_balance(&*state, &acc.address);
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
