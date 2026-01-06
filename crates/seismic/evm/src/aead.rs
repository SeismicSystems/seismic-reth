//! AEAD (Authenticated Encryption with Additional Data) support for Seismic transactions.

use alloy_primitives::Bytes;
use seismic_alloy_consensus::TxSeismicMetadata;
use seismic_enclave::{
    ecdh_decrypt_aead, ecdh_encrypt_aead,
    secp256k1::{PublicKey, SecretKey},
    Nonce,
};

/// Errors that can occur during AEAD encryption/decryption.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AeadError {
    /// Failed to encrypt data with AEAD.
    #[error("AEAD encryption failed: {0}")]
    EncryptionFailed(String),
    /// Failed to decrypt data with AEAD.
    #[error("AEAD decryption failed: {0}")]
    DecryptionFailed(String),
    /// Failed to encode metadata for AEAD.
    #[error("Metadata encoding failed: {0}")]
    MetadataEncodingFailed(String),
}

/// Configuration for AEAD encryption of seismic transactions.
#[derive(Debug, Clone)]
pub struct AeadConfig {
    /// Whether to enforce AEAD for all seismic transactions.
    pub enforce_aead: bool,
    /// Whether to validate metadata during decryption.
    pub validate_metadata: bool,
}

impl Default for AeadConfig {
    fn default() -> Self {
        Self { enforce_aead: true, validate_metadata: true }
    }
}

/// AEAD encryption engine for Seismic transactions.
#[derive(Debug, Clone)]
pub struct SeismicAeadEngine {
    config: AeadConfig,
}

impl SeismicAeadEngine {
    /// Creates a new AEAD engine with the given configuration.
    pub fn new(config: AeadConfig) -> Self {
        Self { config }
    }

    /// Creates a new AEAD engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AeadConfig::default())
    }

    /// Encrypts seismic transaction calldata using AEAD with transaction metadata as additional
    /// authenticated data.
    ///
    /// This function provides authenticated encryption where the transaction metadata is
    /// cryptographically bound to the encrypted calldata, preventing tampering and replay attacks.
    ///
    /// # Arguments
    /// * `public_key` - The recipient's public key for ECDH key derivation
    /// * `secret_key` - The sender's secret key for ECDH key derivation
    /// * `calldata` - The transaction calldata to encrypt
    /// * `nonce` - The encryption nonce
    /// * `metadata` - The transaction metadata to authenticate
    ///
    /// # Returns
    /// * `Ok(Bytes)` - The encrypted calldata with authentication tag
    /// * `Err(AeadError)` - If encryption fails
    pub fn encrypt_calldata(
        &self,
        public_key: &PublicKey,
        secret_key: &SecretKey,
        calldata: &[u8],
        nonce: Nonce,
        metadata: &TxSeismicMetadata,
    ) -> Result<Bytes, AeadError> {
        // Use proper RLP encoding for additional authenticated data
        let aad = metadata.encode_as_aad();

        // Perform AEAD encryption
        let encrypted_data = ecdh_encrypt_aead(public_key, secret_key, calldata, nonce, &aad)
            .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?;

        Ok(Bytes::from(encrypted_data))
    }

    /// Decrypts seismic transaction calldata using AEAD with metadata verification.
    ///
    /// This function verifies the authentication tag to ensure the encrypted calldata
    /// has not been tampered with and that the metadata matches what was originally authenticated.
    ///
    /// # Arguments
    /// * `public_key` - The sender's public key for ECDH key derivation
    /// * `secret_key` - The recipient's secret key for ECDH key derivation
    /// * `encrypted_calldata` - The encrypted calldata with authentication tag
    /// * `nonce` - The decryption nonce
    /// * `metadata` - The transaction metadata to verify against
    ///
    /// # Returns
    /// * `Ok(Bytes)` - The decrypted calldata
    /// * `Err(AeadError)` - If decryption or verification fails
    pub fn decrypt_calldata(
        &self,
        public_key: &PublicKey,
        secret_key: &SecretKey,
        encrypted_calldata: &[u8],
        nonce: Nonce,
        metadata: &TxSeismicMetadata,
    ) -> Result<Bytes, AeadError> {
        // Use proper RLP encoding for additional authenticated data
        let aad = metadata.encode_as_aad();

        // Perform AEAD decryption
        let decrypted_data =
            ecdh_decrypt_aead(public_key, secret_key, encrypted_calldata, nonce, &aad)
                .map_err(|e| AeadError::DecryptionFailed(e.to_string()))?;

        Ok(Bytes::from(decrypted_data))
    }



    /// Returns the current AEAD configuration.
    pub fn config(&self) -> &AeadConfig {
        &self.config
    }

    /// Checks if AEAD enforcement is enabled.
    pub fn is_aead_enforced(&self) -> bool {
        self.config.enforce_aead
    }

    /// Checks if metadata validation is enabled.
    pub fn is_metadata_validation_enabled(&self) -> bool {
        self.config.validate_metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{aliases::U96, ChainId, TxKind, U256};
    use seismic_alloy_consensus::{TxSeismicElements, TxSeismicMetadata};
    use seismic_enclave::{get_unsecure_sample_secp256k1_pk, get_unsecure_sample_secp256k1_sk};

    fn create_test_metadata() -> TxSeismicMetadata {
        TxSeismicMetadata {
            chain_id: 1,
            nonce: 42,
            gas_price: 20_000_000_000u128, // 20 gwei
            gas_limit: 21_000u64,
            to: TxKind::Call(alloy_primitives::Address::ZERO),
            value: alloy_primitives::U256::ZERO,
            seismic_elements: TxSeismicElements {
                encryption_pubkey: get_unsecure_sample_secp256k1_pk(),
                encryption_nonce: U96::from(12345u64),
                message_version: 1,
                recent_block_hash: [1u8; 32].into(),
                expires_at_block: 1000,
                signed_read: false,
            },
        }
    }

    #[test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let engine = SeismicAeadEngine::with_defaults();

        let public_key = get_unsecure_sample_secp256k1_pk();
        let secret_key = get_unsecure_sample_secp256k1_sk();
        let calldata = b"test calldata";
        let nonce = Nonce::new_rand();
        let metadata = create_test_metadata();

        // Encrypt
        let encrypted = engine
            .encrypt_calldata(&public_key, &secret_key, calldata, nonce.clone(), &metadata)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted = engine
            .decrypt_calldata(&public_key, &secret_key, &encrypted, nonce, &metadata)
            .expect("Decryption should succeed");

        assert_eq!(decrypted.as_ref(), calldata);
    }

    #[test]
    fn test_aead_metadata_tampering_detection() {
        let engine = SeismicAeadEngine::with_defaults();

        let public_key = get_unsecure_sample_secp256k1_pk();
        let secret_key = get_unsecure_sample_secp256k1_sk();
        let calldata = b"test calldata";
        let nonce = Nonce::new_rand();
        let original_metadata = create_test_metadata();

        // Encrypt with original metadata
        let encrypted = engine
            .encrypt_calldata(&public_key, &secret_key, calldata, nonce.clone(), &original_metadata)
            .expect("Encryption should succeed");

        // Create tampered metadata
        let mut tampered_metadata = original_metadata.clone();
        tampered_metadata.nonce = 999; // Change nonce

        // Decrypt with tampered metadata should fail
        let result = engine.decrypt_calldata(
            &public_key,
            &secret_key,
            &encrypted,
            nonce,
            &tampered_metadata,
        );

        assert!(result.is_err());
        match result {
            Err(AeadError::DecryptionFailed(_)) => {
                // Expected - AEAD should detect metadata tampering
            }
            _ => panic!("Expected DecryptionFailed error"),
        }
    }

    #[test]
    fn test_aead_with_disabled_metadata_validation() {
        let config = AeadConfig { enforce_aead: true, validate_metadata: false };
        let engine = SeismicAeadEngine::new(config);

        let public_key = get_unsecure_sample_secp256k1_pk();
        let secret_key = get_unsecure_sample_secp256k1_sk();
        let calldata = b"test calldata";
        let nonce = Nonce::new_rand();
        let original_metadata = create_test_metadata();

        // Encrypt with original metadata
        let encrypted = engine
            .encrypt_calldata(&public_key, &secret_key, calldata, nonce.clone(), &original_metadata)
            .expect("Encryption should succeed");

        // Create different metadata
        let mut different_metadata = original_metadata.clone();
        different_metadata.nonce = 999;

        // Decrypt with different metadata should succeed when validation is disabled
        let decrypted = engine
            .decrypt_calldata(&public_key, &secret_key, &encrypted, nonce, &different_metadata)
            .expect("Decryption should succeed with disabled validation");

        assert_eq!(decrypted.as_ref(), calldata);
    }

    #[test]
    fn test_metadata_encoding() {
        let engine = SeismicAeadEngine::with_defaults();
        let metadata = create_test_metadata();

        let aad1 = engine.encode_metadata_aad(&metadata).expect("Encoding should succeed");
        let aad2 = engine.encode_metadata_aad(&metadata).expect("Encoding should succeed");

        // Encoding should be deterministic
        assert_eq!(aad1, aad2);

        // Different metadata should produce different AAD
        let mut different_metadata = metadata.clone();
        different_metadata.nonce = 999;
        let aad3 =
            engine.encode_metadata_aad(&different_metadata).expect("Encoding should succeed");
        assert_ne!(aad1, aad3);
    }

    #[test]
    fn test_create_metadata() {
        let engine = SeismicAeadEngine::with_defaults();

        let chain_id = 1;
        let nonce = 42;
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: get_unsecure_sample_secp256k1_pk(),
            encryption_nonce: U96::from(12345u64),
            message_version: 1,
            recent_block_hash: [1u8; 32].into(),
            expires_at_block: 1000,
            signed_read: true,
        };

        let metadata = TxSeismicMetadata {
            chain_id,
            nonce,
            gas_price: 20_000_000_000u128, // 20 gwei
            gas_limit: 21_000u64,
            to: TxKind::Call(alloy_primitives::Address::ZERO),
            value: alloy_primitives::U256::ZERO,
            seismic_elements: seismic_elements.clone(),
        };

        assert_eq!(metadata.chain_id, chain_id);
        assert_eq!(metadata.nonce, nonce);
        assert_eq!(metadata.seismic_elements, seismic_elements);
    }

    #[test]
    fn test_aead_config() {
        let config = AeadConfig { enforce_aead: false, validate_metadata: true };
        let engine = SeismicAeadEngine::new(config.clone());

        assert_eq!(engine.config().enforce_aead, config.enforce_aead);
        assert_eq!(engine.config().validate_metadata, config.validate_metadata);
        assert_eq!(engine.is_aead_enforced(), false);
        assert_eq!(engine.is_metadata_validation_enabled(), true);
    }
}
