//! Security validation for Seismic transactions.

use crate::SeismicTransactionSigned;
use alloy_primitives::B256;
use reth_chainspec::ChainSpec;
use reth_primitives_traits::BlockHeader;
use seismic_alloy_consensus::{InputDecryptionElements, TxSeismicElements};
use std::{string::ToString, sync::Arc};

/// Validation errors for Seismic transactions.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SeismicValidationError {
    /// Transaction has expired based on block number.
    #[error(
        "Transaction expired: current block {current_block} >= expiry block {expires_at_block}"
    )]
    TransactionExpired {
        /// Current block number
        current_block: u64,
        /// Block at which transaction expires
        expires_at_block: u64,
    },
    /// Recent block hash doesn't match any recent block.
    #[error("Invalid recent block hash: {recent_block_hash}")]
    InvalidRecentBlockHash {
        /// The invalid block hash
        recent_block_hash: B256,
    },
    /// Transaction is missing seismic elements required for validation.
    #[error("Missing seismic elements for validation")]
    MissingSeismicElements,
    /// Error getting decryption elements from transaction.
    #[error("Failed to get decryption elements: {0}")]
    DecryptionElementsError(String),
    /// Incoming seismic transaction cannot be signed_read.
    #[error("Incoming seismic transaction cannot be signed_read")]
    IncomingTransactionCannotBeSignedRead,
    /// Signed read call must be marked as signed_read transaction.
    #[error("Signed read call must be marked as signed_read transaction")]
    SignedReadCallNotMarked,
}

/// Validator for Seismic transaction security constraints.
#[derive(Debug)]
pub struct SeismicTransactionValidator {
    chain_spec: Arc<ChainSpec>,
    /// Maximum number of blocks a transaction can reference as "recent".
    max_recent_block_age: u64,
}

impl SeismicTransactionValidator {
    /// Creates a new Seismic transaction validator.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            chain_spec,
            // Allow transactions to reference blocks up to 256 blocks old
            max_recent_block_age: 256,
        }
    }

    /// Creates a new validator with custom recent block age limit.
    pub fn new_with_recent_block_age(
        chain_spec: Arc<ChainSpec>,
        max_recent_block_age: u64,
    ) -> Self {
        Self { chain_spec, max_recent_block_age }
    }

    /// Validates a seismic transaction against security constraints.
    ///
    /// This function validates:
    /// 1. Transaction expiration based on block number
    /// 2. Recent block hash validity (if enabled)
    ///
    /// # Arguments
    /// * `tx` - The seismic transaction to validate
    /// * `current_block_number` - Current block number
    /// * `recent_block_provider` - Optional provider for recent block hashes
    ///
    /// # Returns
    /// * `Ok(())` if transaction is valid
    /// * `Err(SeismicValidationError)` if validation fails
    pub fn validate_transaction<F>(
        &self,
        tx: &SeismicTransactionSigned,
        current_block_number: u64,
        recent_block_provider: Option<F>,
    ) -> Result<(), SeismicValidationError>
    where
        F: Fn(u64) -> Option<B256>,
    {
        // Get seismic elements from transaction
        let seismic_elements = tx
            .get_decryption_elements()
            .map_err(|e| SeismicValidationError::DecryptionElementsError(e.to_string()))?;

        self.validate_block_constraints(
            &seismic_elements,
            current_block_number,
            recent_block_provider,
        )
    }

    /// Validates block-related security constraints for seismic transactions.
    ///
    /// This function enforces:
    /// 1. Transaction expiration: transactions must not have passed their expiry block
    /// 2. Recent block hash validation: if enabled, the referenced recent block hash must match a
    ///    known recent block
    ///
    /// # Arguments
    /// * `seismic_elements` - The seismic transaction elements containing security fields
    /// * `current_block_number` - Current block number for validation
    /// * `recent_block_provider` - Optional provider function that returns block hash for a given
    ///   block number
    ///
    /// # Returns
    /// * `Ok(())` if all constraints are satisfied
    /// * `Err(SeismicValidationError)` if any constraint fails
    pub fn validate_block_constraints<F>(
        &self,
        seismic_elements: &TxSeismicElements,
        current_block_number: u64,
        recent_block_provider: Option<F>,
    ) -> Result<(), SeismicValidationError>
    where
        F: Fn(u64) -> Option<B256>,
    {
        // 1. Validate transaction expiration
        if current_block_number >= seismic_elements.expires_at_block {
            return Err(SeismicValidationError::TransactionExpired {
                current_block: current_block_number,
                expires_at_block: seismic_elements.expires_at_block,
            });
        }

        // 2. Validate recent block hash (if provider is available)
        if let Some(provider) = recent_block_provider {
            // Find which block number this recent_block_hash corresponds to
            let mut found_matching_block = false;

            // Check recent blocks within the allowed age limit
            let start_block = current_block_number.saturating_sub(self.max_recent_block_age);
            for block_num in start_block..current_block_number {
                if let Some(block_hash) = provider(block_num) {
                    if block_hash == seismic_elements.recent_block_hash {
                        found_matching_block = true;
                        break;
                    }
                }
            }

            if !found_matching_block {
                return Err(SeismicValidationError::InvalidRecentBlockHash {
                    recent_block_hash: seismic_elements.recent_block_hash,
                });
            }
        }

        Ok(())
    }

    /// Returns the chain specification used by this validator.
    pub fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    /// Returns the maximum recent block age configured for this validator.
    pub fn max_recent_block_age(&self) -> u64 {
        self.max_recent_block_age
    }

    /// Validates that an incoming seismic transaction is NOT marked as signed_read.
    ///
    /// Incoming seismic transactions (regular transactions submitted to the mempool)
    /// should never be signed_read transactions, as signed_read is only for read-only calls.
    ///
    /// # Arguments
    /// * `tx` - The seismic transaction to validate
    ///
    /// # Returns
    /// * `Ok(())` if transaction is valid (not signed_read)
    /// * `Err(SeismicValidationError::IncomingTransactionCannotBeSignedRead)` if transaction is
    ///   signed_read
    pub fn validate_incoming_not_signed_read(
        &self,
        tx: &SeismicTransactionSigned,
    ) -> Result<(), SeismicValidationError> {
        let seismic_elements = tx
            .get_decryption_elements()
            .map_err(|e| SeismicValidationError::DecryptionElementsError(e.to_string()))?;

        if seismic_elements.signed_read {
            return Err(SeismicValidationError::IncomingTransactionCannotBeSignedRead);
        }

        Ok(())
    }

    /// Validates that a signed read call is properly marked as signed_read.
    ///
    /// When performing read-only operations (eth_call), the transaction should be
    /// marked as signed_read to indicate it's a read operation and won't modify state.
    ///
    /// # Arguments
    /// * `tx` - The seismic transaction to validate
    ///
    /// # Returns
    /// * `Ok(())` if transaction is valid (marked as signed_read)
    /// * `Err(SeismicValidationError::SignedReadCallNotMarked)` if transaction is not signed_read
    pub fn validate_signed_read_call_marked(
        &self,
        tx: &SeismicTransactionSigned,
    ) -> Result<(), SeismicValidationError> {
        let seismic_elements = tx
            .get_decryption_elements()
            .map_err(|e| SeismicValidationError::DecryptionElementsError(e.to_string()))?;

        if !seismic_elements.signed_read {
            return Err(SeismicValidationError::SignedReadCallNotMarked);
        }

        Ok(())
    }
}

/// Helper trait for validating seismic transactions in different contexts.
pub trait ValidateSeismicTransaction {
    /// Validates a seismic transaction using the current chain state.
    fn validate_seismic_tx(
        &self,
        tx: &SeismicTransactionSigned,
        current_block: &impl BlockHeader,
    ) -> Result<(), SeismicValidationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{aliases::U96, Address, TxKind, U256};
    use seismic_alloy_genesis::Genesis;

    fn create_test_chain_spec() -> Arc<ChainSpec> {
        let genesis = Genesis {
            config: Default::default(),
            nonce: 0,
            timestamp: 0,
            extra_data: Default::default(),
            gas_limit: 0x1388,
            difficulty: Default::default(),
            mix_hash: Default::default(),
            coinbase: Default::default(),
            alloc: Default::default(),
            number: Some(0),
            base_fee_per_gas: Some(7),
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
        };

        Arc::new(
            ChainSpec::builder().chain(1u64.into()).genesis(genesis).shanghai_activated().build(),
        )
    }
    use secp256k1::PublicKey;
    use seismic_alloy_consensus::{SeismicTypedTransaction, TxSeismic};
    use std::str::FromStr;

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
            to: TxKind::Call(
                Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            ),
            value: U256::from(1000),
            input: Default::default(),
            seismic_elements: TxSeismicElements {
                encryption_pubkey: PublicKey::from_str(
                    "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
                )
                .unwrap(),
                encryption_nonce: U96::from(12345u64),
                message_version: 1,
                recent_block_hash,
                expires_at_block,
                signed_read,
            },
        };

        let typed_tx = SeismicTypedTransaction::Seismic(tx);
        SeismicTransactionSigned::new_unhashed(
            typed_tx,
            alloy_primitives::Signature::from_bytes_and_parity(&[1u8; 64], false),
        )
    }

    #[test]
    fn test_transaction_validation_success() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false);

        let current_block = 500;
        let block_provider = |block_num: u64| {
            if block_num == 400 {
                Some(recent_block_hash)
            } else {
                None
            }
        };

        let result = validator.validate_transaction(&tx, current_block, Some(block_provider));
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_expired() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 500, false);

        let current_block = 500; // Transaction expires at block 500, so current block 500 should fail

        let result =
            validator.validate_transaction(&tx, current_block, None::<fn(u64) -> Option<B256>>);

        match result {
            Err(SeismicValidationError::TransactionExpired {
                current_block: cb,
                expires_at_block: eb,
            }) => {
                assert_eq!(cb, 500);
                assert_eq!(eb, 500);
            }
            _ => panic!("Expected TransactionExpired error"),
        }
    }

    #[test]
    fn test_invalid_recent_block_hash() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let wrong_hash =
            B256::from_str("0x9999999999999999999999999999999999999999999999999999999999999999")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false);

        let current_block = 500;
        let block_provider = |_block_num: u64| {
            Some(wrong_hash) // Always return wrong hash
        };

        let result = validator.validate_transaction(&tx, current_block, Some(block_provider));

        match result {
            Err(SeismicValidationError::InvalidRecentBlockHash { recent_block_hash: rbh }) => {
                assert_eq!(rbh, recent_block_hash);
            }
            _ => panic!("Expected InvalidRecentBlockHash error"),
        }
    }

    #[test]
    fn test_validation_without_block_provider() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false);

        let current_block = 500;

        // Should succeed when no block provider is given (skips recent block hash validation)
        let result =
            validator.validate_transaction(&tx, current_block, None::<fn(u64) -> Option<B256>>);
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_transaction_validation() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, true); // signed_read = true

        let current_block = 500;

        let result =
            validator.validate_transaction(&tx, current_block, None::<fn(u64) -> Option<B256>>);
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_constraints_validation() {
        let validator =
            SeismicTransactionValidator::new_with_recent_block_age(create_test_chain_spec(), 10);

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: PublicKey::from_str(
                "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
            )
            .unwrap(),
            encryption_nonce: U96::from(12345u64),
            message_version: 1,
            recent_block_hash,
            expires_at_block: 1000,
            signed_read: false,
        };

        let current_block = 500;
        let block_provider = |block_num: u64| {
            if block_num >= 490 && block_num < 500 {
                // Within recent block age limit
                if block_num == 495 {
                    Some(recent_block_hash)
                } else {
                    Some(B256::from([block_num as u8; 32]))
                }
            } else {
                None
            }
        };

        let result = validator.validate_block_constraints(
            &seismic_elements,
            current_block,
            Some(block_provider),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_recent_block_too_old() {
        let validator =
            SeismicTransactionValidator::new_with_recent_block_age(create_test_chain_spec(), 10);

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: PublicKey::from_str(
                "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
            )
            .unwrap(),
            encryption_nonce: U96::from(12345u64),
            message_version: 1,
            recent_block_hash,
            expires_at_block: 1000,
            signed_read: false,
        };

        let current_block = 500;
        let block_provider = |block_num: u64| {
            if block_num == 480 {
                // Too old (more than 10 blocks)
                Some(recent_block_hash)
            } else {
                Some(B256::from([block_num as u8; 32]))
            }
        };

        let result = validator.validate_block_constraints(
            &seismic_elements,
            current_block,
            Some(block_provider),
        );

        match result {
            Err(SeismicValidationError::InvalidRecentBlockHash { .. }) => {
                // Expected - recent block hash is too old
            }
            _ => panic!("Expected InvalidRecentBlockHash error for too old block"),
        }
    }

    #[test]
    fn test_incoming_transaction_not_signed_read_success() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false); // signed_read = false

        let result = validator.validate_incoming_not_signed_read(&tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incoming_transaction_signed_read_fails() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, true); // signed_read = true

        let result = validator.validate_incoming_not_signed_read(&tx);

        match result {
            Err(SeismicValidationError::IncomingTransactionCannotBeSignedRead) => {
                // Expected
            }
            _ => panic!("Expected IncomingTransactionCannotBeSignedRead error"),
        }
    }

    #[test]
    fn test_signed_read_call_marked_success() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, true); // signed_read = true

        let result = validator.validate_signed_read_call_marked(&tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signed_read_call_not_marked_fails() {
        let validator = SeismicTransactionValidator::new(create_test_chain_spec());

        let recent_block_hash =
            B256::from_str("0x1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        let tx = create_test_seismic_tx(recent_block_hash, 1000, false); // signed_read = false

        let result = validator.validate_signed_read_call_marked(&tx);

        match result {
            Err(SeismicValidationError::SignedReadCallNotMarked) => {
                // Expected
            }
            _ => panic!("Expected SignedReadCallNotMarked error"),
        }
    }
}
