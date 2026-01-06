//! Seismic-specific transaction validation.

use alloy_primitives::B256;
use reth_primitives_traits::BlockHeader;
use reth_seismic_primitives::{SeismicTransactionSigned, SeismicTransactionValidator};

/// Seismic transaction validator that enforces security constraints.
#[derive(Debug)]
pub struct SeismicTxValidator {
    /// Core seismic transaction validator.
    validator: SeismicTransactionValidator,
    /// Whether to enforce block-based validation (expiration, recent block hash).
    enforce_block_validation: bool,
}

impl SeismicTxValidator {
    /// Creates a new seismic transaction validator.
    pub fn new(validator: SeismicTransactionValidator) -> Self {
        Self { validator, enforce_block_validation: true }
    }

    /// Creates a new validator with optional block validation enforcement.
    pub fn new_with_enforcement(
        validator: SeismicTransactionValidator,
        enforce_block_validation: bool,
    ) -> Self {
        Self { validator, enforce_block_validation }
    }

    /// Validates seismic transaction constraints.
    ///
    /// This includes block-based validation (expiration, recent block hash) and
    /// transaction type validation (e.g., incoming transactions should not be signed_read).
    ///
    /// # Arguments
    /// * `tx` - The seismic transaction to validate
    /// * `current_block` - The current block header for validation context
    /// * `block_provider` - Optional function to look up block hashes by number
    ///
    /// # Returns
    /// * `Ok(())` if validation succeeds
    /// * `Err(String)` if validation fails
    pub fn validate_seismic_transaction<F>(
        &self,
        tx: &SeismicTransactionSigned,
        current_block: &impl BlockHeader,
        block_provider: Option<F>,
    ) -> Result<(), String>
    where
        F: Fn(u64) -> Option<B256>,
    {
        // Skip validation if enforcement is disabled (for testing)
        if !self.enforce_block_validation {
            return Ok(());
        }

        // Perform seismic validation
        self.validator
            .validate_transaction(tx, current_block.number(), block_provider)
            .map_err(|e| e.to_string())
    }

    /// Validates that an incoming transaction is not signed_read.
    pub fn validate_incoming_not_signed_read(
        &self,
        tx: &SeismicTransactionSigned,
    ) -> Result<(), String> {
        self.validator.validate_incoming_not_signed_read(tx).map_err(|e| e.to_string())
    }

    /// Validates that a read call transaction is marked as signed_read.
    pub fn validate_read_call_signed(&self, tx: &SeismicTransactionSigned) -> Result<(), String> {
        self.validator.validate_signed_read_call_marked(tx).map_err(|e| e.to_string())
    }
}

/// Trait for seismic transaction validation in different contexts.
pub trait SeismicTransactionValidation {
    /// Validates a seismic transaction.
    fn validate_seismic_tx(
        &self,
        tx: &SeismicTransactionSigned,
        current_block: &impl BlockHeader,
    ) -> Result<(), String>;
}
