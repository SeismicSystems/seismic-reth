//! Seismic transaction validator

use crate::recent_block_cache::RecentBlockCache;
use alloy_consensus::BlockHeader;
use alloy_primitives::{Sealable, B256, U256};
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, Block, GotExpected};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use reth_seismic_primitives::{transaction::error::SeismicTxError, SeismicTransactionSigned};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    validate::{TransactionValidationOutcome, TransactionValidator},
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin,
};
use seismic_alloy_consensus::SeismicTxType;
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
                        // TODO: the recent_block_hash and expires_at_block checks below
                        // are currently only done here in the mempool. They should instead be
                        // done in consensus / block-level validation (e.g. a `SeismicBlockExecutor`
                        // pre-flight) so that since otherwise they can be
                        // bypassed by directly including txs via the builder API or other
                        // non-mempool paths.
                        let seismic_elements = &seismic_tx.seismic_elements;

                        // Validate recent_block_hash is in the last 100 blocks
                        if let Err(err) =
                            self.validate_recent_block_hash(seismic_elements.recent_block_hash)
                        {
                            return TransactionValidationOutcome::Invalid(
                                valid_tx.into_transaction(),
                                err,
                            );
                        }

                        // Validate expires_at_block is not in the past
                        if let Err(err) =
                            self.validate_expiration(seismic_elements.expires_at_block)
                        {
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

impl<Client, Tx> SeismicTransactionValidator<Client, Tx> {
    /// Validates that the `recent_block_hash` field provided in a Seismic tx
    /// is in the last `SEISMIC_TX_RECENT_BLOCK_LOOKBACK` blocks.
    ///
    /// Uses an in-memory cache populated at startup and updated via `on_new_head_block`
    /// for O(1) lookup.
    fn validate_recent_block_hash(
        &self,
        recent_block_hash: B256,
    ) -> Result<(), InvalidPoolTransactionError> {
        let cache = self.recent_blocks.read().unwrap_or_else(|e| e.into_inner());
        if cache.contains(&recent_block_hash) {
            return Ok(());
        }

        let err = SeismicTxError::RecentBlockHashNotFound {
            hash: recent_block_hash,
            lookback: crate::SEISMIC_TX_RECENT_BLOCK_LOOKBACK,
        };
        Err(InvalidTransactionError::SeismicTx(err.to_string()).into())
    }

    /// Validates that the transaction has not expired.
    ///
    /// Uses the cache's `current_block_number` (updated via `on_new_head_block`) so that
    /// both hash validation and expiration check use the same consensus-driven source.
    fn validate_expiration(
        &self,
        expires_at_block: u64,
    ) -> Result<(), InvalidPoolTransactionError> {
        let current_block_num =
            self.recent_blocks.read().unwrap_or_else(|e| e.into_inner()).current_block_number();

        if current_block_num > expires_at_block {
            let err = SeismicTxError::TransactionExpired {
                current_block: current_block_num,
                expires_at_block,
            };
            return Err(InvalidTransactionError::SeismicTx(err.to_string()).into());
        }

        Ok(())
    }
}
