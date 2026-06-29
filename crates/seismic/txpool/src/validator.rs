//! Seismic transaction validator

use crate::recent_block_cache::RecentBlockCache;
use alloy_consensus::BlockHeader;
use alloy_primitives::{Sealable, U256};
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, Block, GotExpected};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use reth_seismic_primitives::{transaction::error::SeismicTxError, SeismicTransactionSigned};
use reth_transaction_pool::{
    validate::{TransactionValidationOutcome, TransactionValidator},
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin,
};
use seismic_alloy_consensus::{SeismicTxType, TxSeismicElements};
use std::{
    fmt,
    marker::PhantomData,
    sync::{Arc, RwLock},
};

/// Seismic transaction validator that adds seismic-specific validation on top of Ethereum
/// validation.
pub struct SeismicTransactionValidator<Client, T> {
    /// Inner Ethereum transaction validator
    inner: Arc<EthTransactionValidator<Client, T>>,
    /// Cache of recent block hashes for O(1) validation
    recent_blocks: RwLock<RecentBlockCache>,
    /// Phantom data for transaction type
    _pd: PhantomData<T>,
}

impl<Client, T> fmt::Debug for SeismicTransactionValidator<Client, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeismicTransactionValidator")
            .field("inner", &"EthTransactionValidator")
            .field("recent_blocks", &"RwLock<RecentBlockCache>")
            .finish()
    }
}

impl<Client, T> SeismicTransactionValidator<Client, T>
where
    Client: BlockReaderIdExt,
{
    /// Creates a new seismic transaction validator wrapping an Ethereum validator.
    ///
    /// Pre-populates the recent block hash cache from the client so that validation
    /// works immediately without a cold-start fallback.
    pub fn new(inner: EthTransactionValidator<Client, T>) -> Self {
        let mut cache = RecentBlockCache::default();

        // Populate cache from the current canonical chain
        if let Ok(tip) = inner.client().best_block_number() {
            cache.rebuild_to_tip(tip, |n| {
                inner.client().header_by_number(n).ok()?.map(|h| h.hash_slow())
            });
        }

        Self { inner: Arc::new(inner), recent_blocks: RwLock::new(cache), _pd: PhantomData }
    }

    /// Get a reference to the inner validator
    pub fn inner(&self) -> &EthTransactionValidator<Client, T> {
        &self.inner
    }
}

impl<Client, Tx> TransactionValidator for SeismicTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory
        + BlockReaderIdExt
        + ChainSpecProvider<ChainSpec: reth_chainspec::EthereumHardforks>
        + Clone
        + 'static,
    Tx: EthPoolTransaction<Consensus = SeismicTransactionSigned> + fmt::Debug,
{
    type Transaction = Tx;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // First run the standard Ethereum validation
        let outcome = self.inner.validate_transaction(origin, transaction).await;

        // If the standard validation failed, return early
        match outcome {
            TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                transaction: valid_tx,
                propagate,
                bytecode_hash,
                authorities,
            } => {
                // Validation passed, continue with seismic-specific checks
                let consensus_tx = valid_tx.transaction().clone_into_consensus();

                // Only validate seismic transactions
                if consensus_tx.tx_type() == SeismicTxType::Seismic {
                    // Get seismic elements from the transaction
                    if let seismic_alloy_consensus::SeismicTypedTransaction::Seismic(seismic_tx) =
                        consensus_tx.transaction()
                    {
                        let seismic_elements = &seismic_tx.seismic_elements;

                        // Freshness check, shared with the eviction task. `is_complete()` gates the
                        // recent_block_hash check so a transient cache hole can't reject a valid
                        // tx.
                        let freshness = {
                            let cache =
                                self.recent_blocks.read().unwrap_or_else(|e| e.into_inner());
                            seismic_freshness_error(seismic_elements, &cache, cache.is_complete())
                        };
                        if let Some(err) = freshness {
                            return TransactionValidationOutcome::Invalid(
                                valid_tx.into_transaction(),
                                InvalidTransactionError::SeismicTx(err.to_string()).into(),
                            );
                        }
                    }
                }

                // Gas on Seismic can be paid in native token or USDC, but the
                // transferred value always comes out of the native balance, so
                // affordability is checked component-wise (see `usdc::can_afford`).
                let sender = *valid_tx.transaction().sender_ref();
                let cost = *valid_tx.transaction().cost();
                let value = valid_tx.transaction().value();
                // `cost` is gas + blob + value, so stripping value leaves the
                // maximum gas (incl. blob) cost.
                let gas_cost = cost.saturating_sub(value);
                let usdc = match self.inner.client().latest() {
                    Ok(state) => crate::usdc::read_usdc_balance(&*state, &sender),
                    // If we can't read state, fall back to native balance only:
                    // usdc = 0 degrades `can_afford` to `native >= cost`.
                    Err(err) => {
                        tracing::warn!(
                            target: "seismic::txpool",
                            %err,
                            %sender,
                            "failed to read state for USDC balance check, defaulting to zero"
                        );
                        U256::ZERO
                    }
                };

                tracing::debug!(
                    target: "seismic::txpool",
                    %sender,
                    tx_hash = %valid_tx.hash(),
                    native_balance = %balance,
                    usdc_scaled_balance = %usdc,
                    gas_cost = %gas_cost,
                    value = %value,
                    "seismic validator affordability check"
                );

                if !crate::usdc::can_afford(balance, usdc, gas_cost, value) {
                    tracing::debug!(
                        target: "seismic::txpool",
                        %sender,
                        tx_hash = %valid_tx.hash(),
                        native_balance = %balance,
                        usdc_scaled_balance = %usdc,
                        gas_cost = %gas_cost,
                        value = %value,
                        "rejecting tx: balances insufficient for gas cost and value"
                    );
                    // The error carries a single got/expected pair, so report the
                    // native-token shortfall: `got` is the native balance, `expected`
                    // the minimum native balance that would make the tx affordable
                    // given the current USDC balance — just the value if USDC covers
                    // gas, the full cost otherwise.
                    let expected = if usdc >= gas_cost { value } else { cost };
                    return TransactionValidationOutcome::Invalid(
                        valid_tx.into_transaction(),
                        InvalidTransactionError::InsufficientFunds(
                            GotExpected { got: balance, expected }.into(),
                        )
                        .into(),
                    );
                }

                TransactionValidationOutcome::Valid {
                    // The pool tracks one balance scalar per sender, so the
                    // component-wise rule isn't expressible. Report native + usdc:
                    // a sound upper bound (`can_afford ⟹ cost ≤ native + usdc`), so
                    // any admitted tx also clears the pool's `cost ≤ balance`
                    // promotion check instead of stranding in the Queued subpool.
                    // Over-approximates across multiple txs from one sender, but
                    // block building is the final affordability gate. Keep in sync
                    // with `SeismicBalanceHook` (maintain.rs).
                    balance: balance.saturating_add(usdc),
                    state_nonce,
                    transaction: valid_tx,
                    propagate,
                    bytecode_hash,
                    authorities,
                }
            }
            // For invalid or error outcomes, pass through
            other => other,
        }
    }

    fn on_new_head_block<B>(&self, new_tip_block: &reth_primitives_traits::SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block);

        let mut cache = self.recent_blocks.write().unwrap_or_else(|e| e.into_inner());
        cache.update(new_tip_block.hash(), new_tip_block.header().number(), |n| {
            self.inner.client().header_by_number(n).ok()?.map(|h| h.hash_slow())
        });
    }
}

/// Freshness violation for `elements`, or `None` if fresh (`recent_block_hash` in window, not
/// expired). Shared by ingress and the eviction task. `check_recent_hash` gates the hash check so a
/// transient cache hole isn't read as staleness; expiry always applies.
pub(crate) fn seismic_freshness_error(
    elements: &TxSeismicElements,
    cache: &RecentBlockCache,
    check_recent_hash: bool,
) -> Option<SeismicTxError> {
    if check_recent_hash && !cache.contains(&elements.recent_block_hash) {
        return Some(SeismicTxError::RecentBlockHashNotFound {
            hash: elements.recent_block_hash,
            lookback: crate::SEISMIC_TX_RECENT_BLOCK_LOOKBACK,
        });
    }

    let current_block = cache.current_block_number();
    if current_block > elements.expires_at_block {
        return Some(SeismicTxError::TransactionExpired {
            current_block,
            expires_at_block: elements.expires_at_block,
        });
    }

    None
}

#[cfg(test)]
#[allow(clippy::panic)] // Test code - panic on failure is acceptable
mod tests {
    use super::*;
    use crate::SeismicPooledTransaction;
    use alloy_consensus::{transaction::Recovered, SignableTransaction, TxLegacy};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, Bytes, FlaggedStorage, Signature, TxKind};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, error::InvalidPoolTransactionError,
        validate::EthTransactionValidatorBuilder, TransactionOrigin,
    };

    const GAS_LIMIT: u64 = 100_000;
    const GAS_PRICE: u128 = 10_000_000_000; // 10 gwei
    /// Maximum gas cost of the test transaction: `GAS_LIMIT * GAS_PRICE` = 10^15 wei.
    const GAS_COST: u128 = GAS_LIMIT as u128 * GAS_PRICE;
    /// Raw 6-decimal USDC amount that scales to exactly [`GAS_COST`] (scaling is 10^12).
    const USDC_RAW_GAS_COST: u128 = GAS_COST / 1_000_000_000_000;
    const ONE_ETH: u128 = 1_000_000_000_000_000_000;

    fn sender() -> Address {
        Address::with_last_byte(0x42)
    }

    /// Validates a legacy transfer of `value` against a mock state where the
    /// sender holds `native` wei and `usdc_raw` 6-decimal USDC units.
    ///
    /// Uses a legacy (non-Seismic-type) transaction so the affordability check
    /// is exercised without needing a recent-block-hash cache entry.
    async fn validate_with(
        native: U256,
        usdc_raw: U256,
        value: U256,
    ) -> TransactionValidationOutcome<SeismicPooledTransaction> {
        let sender = sender();
        let client = MockEthProvider::default().with_chain_spec(SEISMIC_MAINNET.clone());
        client.add_account(sender, ExtendedAccount::new(0, native));
        client.add_account(
            crate::usdc::USDC_CONTRACT,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                crate::usdc::usdc_balance_storage_key(&sender),
                FlaggedStorage::public(usdc_raw),
            )]),
        );

        // Mirror the production pool wiring: the inner Ethereum validator runs
        // with its native balance check disabled, making the seismic validator
        // the sole affordability gate.
        let eth_validator = EthTransactionValidatorBuilder::new(client)
            .no_shanghai()
            .no_cancun()
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        let validator = SeismicTransactionValidator::new(eth_validator);

        let tx = TxLegacy {
            chain_id: Some(5123),
            nonce: 0,
            gas_price: GAS_PRICE,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(Address::with_last_byte(0x43)),
            value,
            input: Bytes::new(),
        };
        // The validator never recovers the signer (it trusts `Recovered`), so a
        // dummy signature is sufficient.
        let signature = Signature::new(U256::from(1), U256::from(1), false);
        let signed: SeismicTransactionSigned =
            SignableTransaction::into_signed(tx, signature).into();
        let recovered = Recovered::new_unchecked(signed, sender);
        let encoded_length = recovered.encode_2718_len();
        let pooled = SeismicPooledTransaction::new(recovered, encoded_length);

        validator.validate_transaction(TransactionOrigin::External, pooled).await
    }

    /// Asserts the outcome is an `InsufficientFunds` rejection and returns the
    /// reported `(got, expected)` balances.
    fn expect_insufficient_funds(
        outcome: TransactionValidationOutcome<SeismicPooledTransaction>,
    ) -> (U256, U256) {
        match outcome {
            TransactionValidationOutcome::Invalid(
                _,
                InvalidPoolTransactionError::Consensus(InvalidTransactionError::InsufficientFunds(
                    err,
                )),
            ) => (err.got, err.expected),
            other => panic!("expected InsufficientFunds rejection, got: {other:?}"),
        }
    }

    /// Native covers the value exactly and USDC covers gas exactly. Neither
    /// balance alone covers gas + value, but component-wise the tx is payable.
    #[tokio::test]
    async fn accepts_when_native_covers_value_and_usdc_covers_gas() {
        let outcome =
            validate_with(U256::from(ONE_ETH), U256::from(USDC_RAW_GAS_COST), U256::from(ONE_ETH))
                .await;
        match outcome {
            TransactionValidationOutcome::Valid { balance, .. } => {
                // pool-tracked scalar is native + usdc_scaled (a sound upper bound
                // on cost; see the `Valid` arm in the validator)
                assert_eq!(balance, U256::from(ONE_ETH) + U256::from(GAS_COST));
            }
            other => panic!("expected Valid outcome, got: {other:?}"),
        }
    }

    /// USDC alone covers gas + value, but the value transfer can only be paid
    /// in native token: the tx could never execute and must be rejected.
    #[tokio::test]
    async fn rejects_when_usdc_covers_cost_but_native_below_value() {
        let native = U256::from(ONE_ETH - 1);
        // 2 ETH worth of USDC (raw 6-decimal units), well above gas + value
        let usdc_raw = U256::from(2 * ONE_ETH / 1_000_000_000_000);
        let outcome = validate_with(native, usdc_raw, U256::from(ONE_ETH)).await;
        let (got, expected) = expect_insufficient_funds(outcome);
        assert_eq!(got, native);
        // USDC covers gas, so the native balance only needs to cover the value
        assert_eq!(expected, U256::from(ONE_ETH));
    }

    /// Native alone covers gas + value with no USDC at all.
    #[tokio::test]
    async fn accepts_when_native_covers_cost_without_usdc() {
        let outcome = validate_with(U256::from(2 * ONE_ETH), U256::ZERO, U256::from(ONE_ETH)).await;
        assert!(
            matches!(outcome, TransactionValidationOutcome::Valid { .. }),
            "expected Valid outcome, got: {outcome:?}"
        );
    }

    /// Native covers the value but nothing more, and USDC is one raw unit short
    /// of the gas cost: unaffordable in every combination.
    #[tokio::test]
    async fn rejects_when_neither_balance_sufficient() {
        let native = U256::from(ONE_ETH);
        let usdc_raw = U256::from(USDC_RAW_GAS_COST - 1);
        let outcome = validate_with(native, usdc_raw, U256::from(ONE_ETH)).await;
        let (got, expected) = expect_insufficient_funds(outcome);
        assert_eq!(got, native);
        // USDC cannot cover gas, so native would need to cover gas + value
        assert_eq!(expected, U256::from(ONE_ETH + GAS_COST));
    }

    /// The common USDC-gas case: no native balance, no value transfer, USDC
    /// covering exactly the gas cost.
    #[tokio::test]
    async fn accepts_usdc_gas_only_with_zero_native() {
        let outcome = validate_with(U256::ZERO, U256::from(USDC_RAW_GAS_COST), U256::ZERO).await;
        assert!(
            matches!(outcome, TransactionValidationOutcome::Valid { .. }),
            "expected Valid outcome, got: {outcome:?}"
        );
    }
}
