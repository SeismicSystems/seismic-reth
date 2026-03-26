/// Header name for the signature.
pub const SIGNATURE_HEADER: &str = "X-Signature";

/// Header name for the nonce.
pub const NONCE_HEADER: &str = "X-Nonce";

/// Trait abstracting over a signature verification scheme.
///
/// Implementors provide signature verification logic for a specific cryptographic scheme
/// (e.g., ed25519, secp256k1). The trait is designed to be used with [`SignatureAuthValidator`].
pub trait SignatureScheme: Clone + Send + 'static {
    /// The public key type for this scheme.
    type PublicKey: Clone + Send + Sync + std::fmt::Debug + 'static;

    /// The signature type for this scheme.
    type Signature: Clone + Send + 'static;

    /// Parse a public key from raw bytes.
    fn parse_public_key(bytes: &[u8]) -> Result<Self::PublicKey, SignatureError>;

    /// Parse a signature from hex-encoded bytes.
    fn parse_signature(hex: &str) -> Result<Self::Signature, SignatureError>;

    /// Verify that `signature` is a valid signature over `message` by `public_key`.
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureError>;
}

/// Errors that can occur during signature validation.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// The signature header is missing or malformed.
    #[error("missing or invalid signature header")]
    MissingSignature,
    /// The nonce header is missing or malformed.
    #[error("missing or invalid nonce header")]
    MissingNonce,
    /// The signature could not be parsed.
    #[error("invalid signature encoding: {0}")]
    InvalidEncoding(String),
    /// The signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),
}

/// ed25519 signature scheme using `ed25519-dalek`.
#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::{SignatureError, SignatureScheme};

    /// ed25519 signature scheme.
    #[derive(Clone, Debug)]
    pub struct Ed25519;

    impl SignatureScheme for Ed25519 {
        type PublicKey = ed25519_dalek::VerifyingKey;
        type Signature = ed25519_dalek::Signature;

        fn parse_public_key(bytes: &[u8]) -> Result<Self::PublicKey, SignatureError> {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| SignatureError::InvalidEncoding("expected 32 bytes for ed25519 public key".into()))?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|e| SignatureError::InvalidEncoding(e.to_string()))
        }

        fn parse_signature(hex: &str) -> Result<Self::Signature, SignatureError> {
            let hex = hex.strip_prefix("0x").unwrap_or(hex);
            let bytes = hex_decode(hex)?;
            let bytes: [u8; 64] = bytes
                .try_into()
                .map_err(|_| SignatureError::InvalidEncoding("expected 64 bytes".into()))?;
            Ok(ed25519_dalek::Signature::from_bytes(&bytes))
        }

        fn verify(
            public_key: &Self::PublicKey,
            message: &[u8],
            signature: &Self::Signature,
        ) -> Result<(), SignatureError> {
            use ed25519_dalek::Verifier;
            public_key
                .verify(message, signature)
                .map_err(|e| SignatureError::VerificationFailed(e.to_string()))
        }
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>, SignatureError> {
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| SignatureError::InvalidEncoding(e.to_string()))
            })
            .collect()
    }
}

/// secp256k1 ECDSA signature scheme using `k256`.
#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::{SignatureError, SignatureScheme};

    /// secp256k1 ECDSA signature scheme.
    #[derive(Clone, Debug)]
    pub struct Secp256k1;

    impl SignatureScheme for Secp256k1 {
        type PublicKey = k256::ecdsa::VerifyingKey;
        type Signature = k256::ecdsa::Signature;

        fn parse_public_key(bytes: &[u8]) -> Result<Self::PublicKey, SignatureError> {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map_err(|e| SignatureError::InvalidEncoding(e.to_string()))
        }

        fn parse_signature(hex: &str) -> Result<Self::Signature, SignatureError> {
            let hex = hex.strip_prefix("0x").unwrap_or(hex);
            let bytes = hex_decode(hex)?;
            k256::ecdsa::Signature::from_slice(&bytes)
                .map_err(|e| SignatureError::InvalidEncoding(e.to_string()))
        }

        fn verify(
            public_key: &Self::PublicKey,
            message: &[u8],
            signature: &Self::Signature,
        ) -> Result<(), SignatureError> {
            use k256::ecdsa::signature::Verifier;
            public_key
                .verify(message, signature)
                .map_err(|e| SignatureError::VerificationFailed(e.to_string()))
        }
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>, SignatureError> {
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| SignatureError::InvalidEncoding(e.to_string()))
            })
            .collect()
    }
}
