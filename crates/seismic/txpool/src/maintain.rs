//! Seismic-specific pool maintenance hook that augments native balances with
//! USDC predeploy balances.

use reth_execution_types::ChangedAccount;
use reth_provider::StateProvider;
use reth_transaction_pool::maintain::ChangedAccountsHook;
use tracing::debug;

/// Makes the transaction pool's balance accounting aware of USDC gas payment.
///
/// On Seismic, gas can be paid in USDC, but the pool tracks a single native
/// balance per account and uses it to promote/demote transactions between the
/// Pending and Queued subpools. Without help, an account paying gas in USDC
/// (with little or no native balance) looks broke to the pool, so its otherwise
/// valid transactions end up parked in the Queued subpool — never promoted to
/// Pending, or demoted back out of it — and are never mined. This
/// [`ChangedAccountsHook`] augments that per-account balance with the sender's
/// USDC balance so those decisions are accurate. It runs in the maintenance loop
/// on new blocks/reorgs and only feeds promote/demote — admission is gated
/// separately by the validator (see [`crate::usdc::can_afford`]).
///
/// The pool's single scalar can't express the validator's component-wise rule
/// (value from native, gas from remaining native or USDC). We report
/// `native + usdc` instead, a sound upper bound: any transaction the validator
/// admits satisfies `cost ≤ native + usdc`, so the pool's `cost ≤ balance` check
/// never parks it in Queued. Keep in sync with the scalar reported by the
/// validator (see `validator.rs`).
///
/// The sum over-promotes only when an account overcommits its *native* balance
/// across multiple value-bearing txs (value=0 gas traffic is gated near-exactly).
/// Such a tx then fails at block building, the final affordability gate. That is
/// safe: an unincluded tx consumes no nonce — it just lingers in the pending
/// subpool and blocks higher nonces from the same sender until balances change
/// (standard stuck-nonce behavior, not on-chain inconsistency).
///
/// Implementation: for each changed account it sets `balance = native + usdc_scaled`
/// ([`crate::usdc::read_usdc_balance`]), reading USDC via the [`StateProvider`] the
/// maintenance loop passes in rather than its own snapshot, so USDC is read from the
/// same block as the native balance and nonce.
#[derive(Debug, Default)]
pub struct SeismicBalanceHook;

impl ChangedAccountsHook for SeismicBalanceHook {
    fn transform(&self, state: &dyn StateProvider, accounts: &mut Vec<ChangedAccount>) {
        for acc in accounts.iter_mut() {
            let usdc = crate::usdc::read_usdc_balance(state, &acc.address);
            let new_balance = acc.balance.saturating_add(usdc);
            if new_balance != acc.balance {
                debug!(
                    target: "seismic::txpool",
                    address = %acc.address,
                    native_balance = %acc.balance,
                    usdc_scaled_balance = %usdc,
                    pool_balance = %new_balance,
                    "augmenting changed account balance with USDC"
                );
                acc.balance = new_balance;
            }
        }
    }
}
