//! Seismic-specific transaction validation.

use alloy_primitives::B256;
use reth_primitives_traits::{BlockHeader, SignedTransaction};
use reth_seismic_primitives::{SeismicTransactionSigned, SeismicValidationError, SeismicTransactionValidator};
use reth_transaction_pool::{
    error::InvalidTransactionError,
    validate::{ValidTransaction, TransactionValidationOutcome, ValidTransactionError},
};
use std::sync::Arc;

/// Seismic transaction validator that enforces security constraints.
#[derive(Debug)]
pub struct SeismicTxValidator {
    /// Core seismic transaction validator.
    validator: SeismicTransactionValidator,
    /// Whether to enforce block validation (can be disabled for testing).
    enforce_block_validation: bool,
}

impl SeismicTxValidator {
    /// Creates a new seismic transaction validator.
    pub fn new(validator: SeismicTransactionValidator) -> Self {
        Self {
            validator,
            enforce_block_validation: true,
        }
    }

    /// Creates a validator with block validation enforcement setting.
    pub fn new_with_enforcement(
        validator: SeismicTransactionValidator,
        enforce_block_validation: bool,
    ) -> Self {
        Self {
            validator,
            enforce_block_validation,
        }
    }

    /// Validates a seismic transaction for inclusion in the transaction pool.
    ///
    /// This function performs seismic-specific validation on top of the standard
    /// Ethereum transaction validation. It validates:
    /// 1. Transaction expiration based on current block
    /// 2. Recent block hash validity (if block provider is available)
    /// 3. Other seismic security constraints
    ///
    /// # Arguments
    /// * `tx` - The seismic transaction to validate
    /// * `current_block` - Current block for validation context
    /// * `block_provider` - Optional provider for recent block hashes
    ///
    /// # Returns
    /// * `Ok(())` if validation succeeds
    /// * `Err(ValidTransactionError)` if validation fails
    pub fn validate_seismic_transaction<F>(
        &self,
        tx: &SeismicTransactionSigned,
        current_block: &impl BlockHeader,
        block_provider: Option<F>,
    ) -> Result<(), ValidTransactionError>
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
            .map_err(|e| match e {
                SeismicValidationError::TransactionExpired { current_block, expires_at_block } => {
                    ValidTransactionError::InvalidTransaction(
                        InvalidTransactionError::OldLegacyChainId(format!(
                            "Transaction expired at block {}, current block is {}",
                            expires_at_block, current_block
                        )),
                    )
                }
                SeismicValidationError::InvalidRecentBlockHash { recent_block_hash } => {
                    ValidTransactionError::InvalidTransaction(
                        InvalidTransactionError::OldLegacyChainId(format!(
                            "Invalid recent block hash: {}",
                            recent_block_hash
                        )),
                    )
                }
                SeismicValidationError::MissingSeismicElements => {
                    ValidTransactionError::InvalidTransaction(
                        InvalidTransactionError::OldLegacyChainId(
                            "Missing seismic elements".to_string()
                        ),
                    )
                }
                SeismicValidationError::DecryptionElementsError(msg) => {
                    ValidTransactionError::InvalidTransaction(
                        InvalidTransactionError::OldLegacyChainId(format!(
                            "Decryption elements error: {}",
                            msg
                        )),
                    )
                }
            })
    }

    /// Returns a reference to the underlying validator.
    pub fn validator(&self) -> &SeismicTransactionValidator {
        &self.validator
    }

    /// Returns whether block validation is enforced.
    pub fn is_block_validation_enforced(&self) -> bool {
        self.enforce_block_validation
    }

    /// Sets the block validation enforcement flag.
    pub fn set_enforce_block_validation(&mut self, enforce: bool) {
        self.enforce_block_validation = enforce;
    }
}

/// Helper trait for extending transaction validation with seismic constraints.
pub trait SeismicTransactionValidation {
    /// Validates seismic-specific transaction constraints.
    fn validate_seismic_constraints(
        &self,
        tx: &SeismicTransactionSigned,
        current_block: &impl BlockHeader,
    ) -> Result<(), ValidTransactionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{Address, TxKind, U256, aliases::U96};
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use secp256k1::PublicKey;
    use seismic_alloy_consensus::{SeismicTypedTransaction, TxSeismic, TxSeismicElements};
    use std::str::FromStr;

    fn create_test_validator() -> SeismicTxValidator {
        let validator = SeismicTransactionValidator::new(SEISMIC_MAINNET.clone());
        SeismicTxValidator::new(validator)
    }

    fn create_test_seismic_tx(
        recent_block_hash: B256,
        expires_at_block: u64,
        signed_read: bool,
    ) -> SeismicTransactionSigned {
        let tx = TxSeismic {
            chain_id: 1,
            nonce: 1,
            gas_price: 21000,
            gas_limit: 21000,
            to: TxKind::Call(Address::from_str("0x0000000000000000000000000000000000000001").unwrap()),
            value: U256::from(1000),
            input: Default::default(),
            seismic_elements: TxSeismicElements {
                encryption_pubkey: PublicKey::from_str("028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0").unwrap(),
                encryption_nonce: U96::from(12345u64),
                message_version: 1,
                recent_block_hash,
                expires_at_block,
                signed_read,
            },
        };

        let typed_tx = SeismicTypedTransaction::Seismic(tx);
        SeismicTransactionSigned::new_unhashed(typed_tx, Default::default())
    }

    fn create_test_block(block_number: u64) -> Header {
        Header {
            number: block_number,
            timestamp: 1234567890,
            gas_limit: 8000000,
            ..Default::default()
        }
    }

    #[test]
    fn test_valid_seismic_transaction() {
        let validator = create_test_validator();
        
        let recent_block_hash = B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234").unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false);
        let current_block = create_test_block(500);
        
        let block_provider = |block_num: u64| {
            if block_num == 400 {
                Some(recent_block_hash)
            } else {
                None
            }
        };

        let result = validator.validate_seismic_transaction(&tx, &current_block, Some(block_provider));
        assert!(result.is_ok());
    }

    #[test]
    fn test_expired_seismic_transaction() {
        let validator = create_test_validator();
        
        let recent_block_hash = B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234").unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 500, false);
        let current_block = create_test_block(500); // Transaction expires at block 500
        
        let result = validator.validate_seismic_transaction(&tx, &current_block, None::<fn(u64) -> Option<B256>>);
        assert!(result.is_err());
        
        match result {
            Err(ValidTransactionError::InvalidTransaction(
                InvalidTransactionError::OldLegacyChainId(msg)
            )) => {
                assert!(msg.contains("expired"));
            }
            _ => panic!("Expected expired transaction error"),
        }
    }

    #[test]
    fn test_invalid_recent_block_hash() {
        let validator = create_test_validator();
        
        let recent_block_hash = B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234").unwrap();
        let wrong_hash = B256::from_str("0x9999999999999999999999999999999999999999999999999999999999999999").unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false);
        let current_block = create_test_block(500);
        
        let block_provider = |_block_num: u64| {
            Some(wrong_hash) // Always return wrong hash
        };

        let result = validator.validate_seismic_transaction(&tx, &current_block, Some(block_provider));
        assert!(result.is_err());
        
        match result {
            Err(ValidTransactionError::InvalidTransaction(
                InvalidTransactionError::OldLegacyChainId(msg)
            )) => {
                assert!(msg.contains("Invalid recent block hash"));
            }
            _ => panic!("Expected invalid recent block hash error"),
        }
    }

    #[test]
    fn test_validation_enforcement_disabled() {
        let seismic_validator = SeismicTransactionValidator::new(SEISMIC_MAINNET.clone());
        let mut validator = SeismicTxValidator::new_with_enforcement(seismic_validator, false);
        
        let recent_block_hash = B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234").unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 100, false); // Expired transaction
        let current_block = create_test_block(500);
        
        // Should pass validation when enforcement is disabled
        let result = validator.validate_seismic_transaction(&tx, &current_block, None::<fn(u64) -> Option<B256>>);
        assert!(result.is_ok());
        
        // Enable enforcement and try again
        validator.set_enforce_block_validation(true);
        let result = validator.validate_seismic_transaction(&tx, &current_block, None::<fn(u64) -> Option<B256>>);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_transaction_validation() {
        let validator = create_test_validator();
        
        let recent_block_hash = B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234").unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, true); // signed_read = true
        let current_block = create_test_block(500);
        
        let result = validator.validate_seismic_transaction(&tx, &current_block, None::<fn(u64) -> Option<B256>>);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validator_properties() {
        let seismic_validator = SeismicTransactionValidator::new(SEISMIC_MAINNET.clone());
        let validator = SeismicTxValidator::new(seismic_validator);
        
        assert!(validator.is_block_validation_enforced());
        assert!(validator.validator().chain_spec().chain().id() > 0);
    }
}