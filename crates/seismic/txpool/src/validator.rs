//! Seismic transaction validator

use alloy_primitives::{Sealable, TxKind, B256};
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, Block};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use reth_seismic_primitives::{
    transaction::error::SeismicTxError, SeismicTransactionSigned,
};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    validate::{TransactionValidationOutcome, TransactionValidator},
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin,
};
use seismic_alloy_consensus::SeismicTxType;
use std::{fmt, marker::PhantomData, sync::Arc};

/// Maximum number of blocks to look back for recent_block_hash validation
pub const SEISMIC_TX_RECENT_BLOCK_LOOKBACK: u64 = 100;

/// Seismic transaction validator that adds seismic-specific validation on top of Ethereum validation.
pub struct SeismicTransactionValidator<Client, T> {
    /// Inner Ethereum transaction validator
    inner: Arc<EthTransactionValidator<Client, T>>,
    /// Phantom data for transaction type
    _pd: PhantomData<T>,
}

impl<Client, T> fmt::Debug for SeismicTransactionValidator<Client, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeismicTransactionValidator")
            .field("inner", &"EthTransactionValidator")
            .finish()
    }
}

impl<Client, T> SeismicTransactionValidator<Client, T> {
    /// Creates a new seismic transaction validator wrapping an Ethereum validator
    pub fn new(inner: EthTransactionValidator<Client, T>) -> Self {
        Self { inner: Arc::new(inner), _pd: PhantomData }
    }

    /// Get a reference to the inner validator
    pub fn inner(&self) -> &EthTransactionValidator<Client, T> {
        &self.inner
    }
}

impl<Client, Tx> TransactionValidator for SeismicTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory + BlockReaderIdExt + ChainSpecProvider<ChainSpec: reth_chainspec::EthereumHardforks> + Clone + 'static,
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

                        // Validate recent_block_hash is in the last 100 blocks
                        if let Err(err) =
                            self.validate_recent_block_hash(seismic_elements.recent_block_hash)
                        {
                            return TransactionValidationOutcome::Invalid(valid_tx.into_transaction(), err);
                        }

                        // Validate expires_at_block is not in the past
                        if let Err(err) =
                            self.validate_expiration(seismic_elements.expires_at_block)
                        {
                            return TransactionValidationOutcome::Invalid(valid_tx.into_transaction(), err);
                        }

                        // Validate signed_read for write transactions
                        if let Err(err) = Self::validate_signed_read_for_write(
                            seismic_tx.to,
                            seismic_elements.signed_read,
                        ) {
                            return TransactionValidationOutcome::Invalid(valid_tx.into_transaction(), err);
                        }
                    }
                }

                // All validations passed, return valid
                TransactionValidationOutcome::Valid {
                    balance,
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
        self.inner.on_new_head_block(new_tip_block)
    }
}

impl<Client, Tx> SeismicTransactionValidator<Client, Tx>
where
    Client: BlockReaderIdExt,
{
    /// Validates that the recent_block_hash is in the last SEISMIC_TX_RECENT_BLOCK_LOOKBACK blocks
    fn validate_recent_block_hash(
        &self,
        recent_block_hash: B256,
    ) -> Result<(), InvalidPoolTransactionError> {
        // Get the current block number
        let current_block_num = self
            .inner
            .client()
            .last_block_number()
            .map_err(|_| InvalidTransactionError::OldLegacyChainId)?;

        // Calculate the earliest acceptable block number
        let earliest_block = current_block_num.saturating_sub(SEISMIC_TX_RECENT_BLOCK_LOOKBACK);

        // Check if the recent_block_hash exists in the last N blocks
        for block_num in earliest_block..=current_block_num {
            if let Ok(Some(header)) = self.inner.client().header_by_number(block_num) {
                if header.hash_slow() == recent_block_hash {
                    return Ok(());
                }
            }
        }

        // If we get here, the recent_block_hash was not found in the last N blocks
        let err = SeismicTxError::RecentBlockHashNotFound {
            hash: recent_block_hash,
            lookback: SEISMIC_TX_RECENT_BLOCK_LOOKBACK,
        };
        Err(InvalidTransactionError::SeismicTx(err.to_string()).into())
    }

    /// Validates that the transaction has not expired
    fn validate_expiration(
        &self,
        expires_at_block: u64,
    ) -> Result<(), InvalidPoolTransactionError> {
        // Get the current block number
        let current_block_num = self
            .inner
            .client()
            .last_block_number()
            .map_err(|_| InvalidTransactionError::OldLegacyChainId)?;

        // Check if the transaction has expired
        if current_block_num > expires_at_block {
            let err = SeismicTxError::TransactionExpired {
                current_block: current_block_num,
                expires_at_block,
            };
            return Err(InvalidTransactionError::SeismicTx(err.to_string()).into());
        }

        Ok(())
    }

    /// Validates that signed_read is false for write transactions (transactions with a `to` address)
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
