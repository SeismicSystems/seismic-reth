//! Registry-aware RPC affordability over the requested simulation database.

use crate::SeismicEthApiError;
use alloy_primitives::{aliases::U512, Address, FlaggedStorage, U256};
use reth_rpc_eth_types::{EthApiError, RpcInvalidTransactionError};
use revm::{context::result::InvalidTransaction, Database};
use seismic_revm::{
    gas_token_registry::{
        lookup_token, token_balance, visit_eligible_tokens, RegistryError, RegistryStorage,
        TokenPrecision,
    },
    transaction::abstraction::SeismicTxTr,
    GasPayment,
};

/// The database is already pinned to the requested block and includes permitted
/// simulation overrides. Never obtain another provider or discard privacy flags.
struct SimulationRegistry<'a, DB>(&'a mut DB);

impl<DB: Database> RegistryStorage for SimulationRegistry<'_, DB> {
    type Error = DB::Error;

    fn read_storage(&mut self, address: Address, key: U256) -> Result<FlaggedStorage, Self::Error> {
        self.0.storage(address, key)
    }
}

/// Deterministic invalidity uses the transaction channel, with no private amounts
/// in public diagnostics. Storage failures keep their original RPC classification.
fn registry_error<E: Into<EthApiError>>(error: RegistryError<E>) -> SeismicEthApiError {
    match error {
        RegistryError::Storage(error) => error.into().into(),
        RegistryError::Transaction(error) => invalid_payment(error).into(),
    }
}

pub(crate) fn insufficient_payment() -> EthApiError {
    RpcInvalidTransactionError::SeismicTx(
        "insufficient funds for the selected gas payment".to_owned(),
    )
    .into()
}

pub(crate) fn invalid_payment(error: InvalidTransaction) -> EthApiError {
    match error {
        InvalidTransaction::LackOfFundForMaxFee { .. } => insufficient_payment(),
        error => RpcInvalidTransactionError::from(error).into(),
    }
}

/// `floor((balance * divisor - fixed fee) / price)`, capped *after* division.
/// Wide intermediates also handle maximum U256 balances without underestimating.
fn asset_allowance(
    balance: U256,
    precision: TokenPrecision,
    fixed_fee: U256,
    price: U256,
    cap: u64,
) -> u64 {
    if fixed_fee.is_zero() {
        return precision.gas_allowance(balance, price, cap).unwrap_or(cap);
    }
    let available = U512::from(balance) * U512::from(precision.divisor());
    let Some(available) = available.checked_sub(U512::from(fixed_fee)) else { return 0 };
    (available / U512::from(price)).min(U512::from(cap)).to::<u64>()
}

/// Allowance is a single-asset bound, not pool aggregate reporting or execution
/// selection. Auto therefore visits *all* eligible balances even after reaching
/// the cap. Native and explicit Token keep their narrower required read frontiers.
pub(super) fn caller_gas_allowance<DB: Database, TX: SeismicTxTr>(
    db: &mut DB,
    tx: &TX,
    cap: u64,
) -> Result<u64, SeismicEthApiError>
where
    DB::Error: Into<EthApiError>,
{
    // Upstream only calls allowance for positive prices. Retain zero-price flow
    // without introducing a registry scan or dividing by zero.
    let price = U256::from(tx.max_fee_per_gas());
    if price.is_zero() {
        return Ok(cap);
    }
    let native = db
        .basic(tx.caller())
        .map_err(Into::<EthApiError>::into)?
        .map(|account| account.balance)
        .unwrap_or_default();
    let native = native
        .checked_sub(tx.value())
        .ok_or(RpcInvalidTransactionError::InsufficientFundsForTransfer)
        .map_err(EthApiError::from)?;
    let selector = tx.gas_payment();
    if selector != GasPayment::Auto && tx.tx_type() != seismic_alloy_consensus::SEISMIC_TX_TYPE_ID {
        return Err(invalid_payment(InvalidTransaction::InvalidGasPaymentSelector).into());
    }
    // Blob funding is additive, and belongs to the *same* asset as execution gas.
    // Use a wide U256 multiplication rather than max_data_fee's u128 saturation.
    let fixed_fee = if tx.tx_type() == 3 {
        U256::from(tx.total_blob_gas()) * U256::from(tx.max_fee_per_blob_gas())
    } else {
        U256::ZERO
    };
    let mut allowance = (native.checked_sub(fixed_fee).unwrap_or_default() / price)
        .min(U256::from(cap))
        .to::<u64>();
    if selector == GasPayment::Native {
        return Ok(allowance);
    }
    let mut reader = SimulationRegistry(db);
    if let GasPayment::Token(address) = selector {
        let token = lookup_token(&mut reader, address).map_err(registry_error)?;
        let balance = token_balance(&mut reader, token, tx.caller()).map_err(registry_error)?;
        if !token.mode.accepts(balance) {
            return Err(invalid_payment(InvalidTransaction::GasTokenBalanceModeMismatch {
                token: address,
                account: tx.caller(),
            })
            .into());
        }
        return Ok(asset_allowance(balance.value, token.precision, fixed_fee, price, cap));
    }
    visit_eligible_tokens(&mut reader, tx.caller(), |token, balance| {
        allowance = allowance.max(asset_allowance(balance, token.precision, fixed_fee, price, cap));
    })
    .map_err(registry_error)?;
    Ok(allowance)
}

#[cfg(test)]
mod tests;
