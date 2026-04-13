//! Screening transaction validator wrapper.
//!
//! [`ScreeningTransactionValidator`] wraps any inner `TransactionValidator` and adds
//! ECSD address screening as an **operator policy** layer. This is separate from
//! protocol invariants enforced by
//! [`SeismicTransactionValidator`](crate::SeismicTransactionValidator).

use super::{
    calldata::{extract_addresses, extract_addresses_with_input},
    client::ScreeningClient,
    metrics::ScreeningMetrics,
};
use alloy_consensus::Transaction;
use alloy_eips::eip2718::Typed2718;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, Block};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    validate::{TransactionValidationOutcome, TransactionValidator},
    PoolTransaction, TransactionOrigin,
};
use seismic_alloy_consensus::{InputDecryptionElements, SeismicTxType};
use seismic_enclave::GetPurposeKeysResponse;
use std::time::Instant;

/// Wraps any `TransactionValidator` and adds ECSD address screening.
///
/// This is an **operator-policy** layer, not a protocol invariant.
/// Validators opt in to screening by enabling it via CLI flags.
///
/// For Seismic transactions with encrypted calldata, the validator attempts
/// decryption before extracting addresses. If decryption fails, screening is
/// skipped (the tx enters the pool unscreened).
///
/// The validation chain is:
/// ```text
/// EthTransactionValidator (Ethereum rules)
///   └── SeismicTransactionValidator (Seismic protocol invariants)
///       └── ScreeningTransactionValidator (operator policy — optional)
/// ```
pub struct ScreeningTransactionValidator<V> {
    /// Inner validator (Seismic + Ethereum).
    inner: V,
    /// gRPC client for the ECSD sidecar.
    client: ScreeningClient,
    /// Purpose keys for decrypting Seismic transaction calldata before screening.
    purpose_keys: &'static GetPurposeKeysResponse,
    /// Runtime metrics.
    metrics: ScreeningMetrics,
}

impl<V: std::fmt::Debug> std::fmt::Debug for ScreeningTransactionValidator<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreeningTransactionValidator")
            .field("inner", &self.inner)
            .field("client", &self.client)
            .finish()
    }
}

impl<V> ScreeningTransactionValidator<V> {
    /// Creates a new screening validator wrapping the given inner validator.
    pub fn new(
        inner: V,
        client: ScreeningClient,
        purpose_keys: &'static GetPurposeKeysResponse,
    ) -> Self {
        Self { inner, client, purpose_keys, metrics: ScreeningMetrics::default() }
    }
}

impl<V> TransactionValidator for ScreeningTransactionValidator<V>
where
    V: TransactionValidator,
    V::Transaction: PoolTransaction<Consensus: InputDecryptionElements>
        + alloy_consensus::Transaction
        + Typed2718,
{
    type Transaction = V::Transaction;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // First run inner validation (Seismic + Ethereum)
        let outcome = self.inner.validate_transaction(origin, transaction).await;

        match outcome {
            TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                transaction: valid_tx,
                propagate,
                bytecode_hash,
                authorities,
            } => {
                let extraction_start = Instant::now();

                // For non-Seismic txs, calldata is already plaintext — extract.
                // For Seismic txs, decrypt first so we can screen real calldata.
                let addresses = if valid_tx.transaction().ty() != SeismicTxType::Seismic as u8 {
                    extract_addresses(valid_tx.transaction())
                } else {
                    let consensus_tx = valid_tx.transaction().clone_into_consensus();
                    let sender = *consensus_tx.signer_ref();
                    match consensus_tx.inner().plaintext_copy(&self.purpose_keys.tx_io_sk, sender) {
                        Ok(plaintext_tx) => extract_addresses_with_input(
                            valid_tx.transaction(),
                            plaintext_tx.input(),
                        ),
                        Err(err) => {
                            // Decryption failed — skip screening entirely.
                            // The tx enters the pool unscreened.
                            tracing::debug!(
                                target: "txpool::screening",
                                tx_hash = %valid_tx.hash(),
                                %err,
                                "skipping screening: calldata decryption failed"
                            );
                            return TransactionValidationOutcome::Valid {
                                balance,
                                state_nonce,
                                transaction: valid_tx,
                                propagate,
                                bytecode_hash,
                                authorities,
                            };
                        }
                    }
                };

                self.metrics
                    .address_extraction_duration
                    .record(extraction_start.elapsed().as_secs_f64());
                self.metrics.addresses_per_request.record(addresses.len() as f64);

                // Format for gRPC
                let addr_strings: Vec<String> =
                    addresses.iter().map(|a| format!("{a:#x}")).collect();

                // Screen via ECSD
                let screening_start = Instant::now();
                let result = self.client.screen_addresses(addr_strings).await;
                let screening_duration = screening_start.elapsed();
                self.metrics.screening_request_duration.record(screening_duration.as_secs_f64());
                self.metrics.screened_transactions.increment(1);

                match result {
                    Ok(flagged) if flagged.is_empty() => {
                        // All clear — pass through
                        TransactionValidationOutcome::Valid {
                            balance,
                            state_nonce,
                            transaction: valid_tx,
                            propagate,
                            bytecode_hash,
                            authorities,
                        }
                    }
                    Ok(flagged) => {
                        self.metrics.flagged_transactions.increment(1);
                        // Log flagged addresses server-side for operator visibility,
                        // but return a generic error to the caller to avoid leaking
                        // which specific addresses are on the blocklist.
                        tracing::info!(
                            target: "txpool::screening",
                            tx_hash = %valid_tx.hash(),
                            ?flagged,
                            "transaction rejected: flagged addresses"
                        );
                        TransactionValidationOutcome::Invalid(
                            valid_tx.into_transaction(),
                            InvalidPoolTransactionError::Consensus(
                                InvalidTransactionError::SeismicTx(
                                    "transaction rejected by address screening".to_string(),
                                ),
                            ),
                        )
                    }
                    Err(err) => {
                        // Only reached in fail-closed mode
                        self.metrics.screening_errors.increment(1);
                        tracing::warn!(
                            target: "txpool::screening",
                            tx_hash = %valid_tx.hash(),
                            %err,
                            "screening sidecar error (fail-closed)"
                        );
                        TransactionValidationOutcome::Invalid(
                            valid_tx.into_transaction(),
                            InvalidPoolTransactionError::Consensus(
                                InvalidTransactionError::SeismicTx(format!(
                                    "screening sidecar unavailable: {err}"
                                )),
                            ),
                        )
                    }
                }
            }
            // Pass through Invalid/Error from inner validator
            other => other,
        }
    }

    fn on_new_head_block<B>(&self, new_tip_block: &reth_primitives_traits::SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block);
    }
}
