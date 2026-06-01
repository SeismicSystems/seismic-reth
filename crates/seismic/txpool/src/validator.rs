//! Seismic transaction validator

use crate::recent_block_cache::RecentBlockCache;
use alloy_consensus::BlockHeader;
use alloy_primitives::{Sealable, TxKind, U256};
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, Block, GotExpected};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use reth_seismic_primitives::{transaction::error::SeismicTxError, SeismicTransactionSigned};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
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

                        // Validate the freshness window. Skip the recent_block_hash check when the
                        // cache window has a hole, so a missing entry can't reject a valid tx; the
                        // executor re-checks against the canonical chain at block building.
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

                        // Validate signed_read for write transactions
                        if let Err(err) = Self::validate_signed_read_for_write(
                            seismic_tx.to,
                            seismic_elements.signed_read,
                        ) {
                            return TransactionValidationOutcome::Invalid(
                                valid_tx.into_transaction(),
                                err,
                            );
                        }
                    }
                }

                // Compute the effective balance: max(native, usdc_scaled).
                // Gas on Seismic can be paid in either native token or USDC, so
                // we consider both when deciding pool admission.
                let sender = *valid_tx.transaction().sender_ref();
                let cost = *valid_tx.transaction().cost();
                let (eff_balance, usdc_raw) = match self.inner.client().latest() {
                    Ok(state) => {
                        let usdc = crate::usdc::read_usdc_balance(&*state, &sender);
                        (std::cmp::max(balance, usdc), usdc)
                    }
                    // If we can't read state, fall back to native balance only.
                    Err(err) => {
                        tracing::warn!(
                            target: "seismic::txpool",
                            %err,
                            %sender,
                            "failed to read state for USDC balance check"
                        );
                        (balance, U256::ZERO)
                    }
                };

                tracing::debug!(
                    target: "seismic::txpool",
                    %sender,
                    tx_hash = %valid_tx.hash(),
                    native_balance = %balance,
                    usdc_scaled_balance = %usdc_raw,
                    effective_balance = %eff_balance,
                    cost = %cost,
                    "seismic validator effective balance check"
                );

                // Reject if the sender cannot afford the transaction with either token.
                if cost > eff_balance {
                    tracing::debug!(
                        target: "seismic::txpool",
                        %sender,
                        tx_hash = %valid_tx.hash(),
                        effective_balance = %eff_balance,
                        cost = %cost,
                        "rejecting tx: effective balance insufficient for cost"
                    );
                    return TransactionValidationOutcome::Invalid(
                        valid_tx.into_transaction(),
                        InvalidTransactionError::InsufficientFunds(
                            GotExpected { got: eff_balance, expected: cost }.into(),
                        )
                        .into(),
                    );
                }

                TransactionValidationOutcome::Valid {
                    balance: eff_balance,
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

/// The freshness violation for `elements` against `cache`, or `None` if fresh: `recent_block_hash`
/// within the lookback window and `expires_at_block` not in the past. Shared by ingress and the
/// eviction task. `check_recent_hash` gates the hash check (ingress passes `true`; eviction passes
/// [`RecentBlockCache::is_complete`], so a cache hole isn't read as staleness). Expiry always
/// applies.
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

impl<Client, Tx> SeismicTransactionValidator<Client, Tx> {
    /// Validates that `signed_read` is false for write transactions (transactions with a `to`
    /// address)
    fn validate_signed_read_for_write(
        to: TxKind,
        signed_read: bool,
    ) -> Result<(), InvalidPoolTransactionError> {
        // If this is a write transaction (has a destination), signed_read must be false
        if !to.is_create() && signed_read {
            let err = SeismicTxError::InvalidSignedReadForWrite;
            return Err(InvalidTransactionError::SeismicTx(err.to_string()).into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{seismic_freshness_error, RecentBlockCache};
    use alloy_primitives::B256;
    use reth_seismic_primitives::{
        test_utils::get_seismic_elements, transaction::error::SeismicTxError,
    };

    #[test]
    fn freshness_guard_gates_recent_hash_check() {
        // Cache covering blocks 0..=10 (none of which is the tx's recent_block_hash).
        let mut cache = RecentBlockCache::new(100);
        cache.rebuild_to_tip(10, |n| Some(B256::from([(n as u8).wrapping_add(1); 32])));
        assert!(cache.is_complete());

        let mut elements = get_seismic_elements(B256::repeat_byte(0xab));
        elements.expires_at_block = 1_000; // not expired (current block is 10)

        // Complete cache: an unknown recent_block_hash is a violation.
        assert!(matches!(
            seismic_freshness_error(&elements, &cache, true),
            Some(SeismicTxError::RecentBlockHashNotFound { .. })
        ));

        // Guard off (cache incomplete): the same miss must NOT be treated as stale.
        assert!(seismic_freshness_error(&elements, &cache, false).is_none());

        // Expiry is always enforced, regardless of the guard.
        elements.expires_at_block = 5; // current block 10 > 5
        assert!(matches!(
            seismic_freshness_error(&elements, &cache, false),
            Some(SeismicTxError::TransactionExpired { .. })
        ));
    }
}
