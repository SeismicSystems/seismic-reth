//! Fuzz tests for seismic precompiles.
//!
//! DEPENDENCIES EXERCISED: [`seismic-revm`, `seismic-crypto`]
//! CRASH CATEGORY: precompile
//!
//! All stateless precompiles have signature `fn(&[u8], u64) -> PrecompileResult`.
//! We feed arbitrary bytes with arbitrary gas limits to verify no panics.
//! The `.expect("must be 12 bytes")` calls in AES precompiles are theoretically
//! guarded by `validate_nonce_length`, but the fuzzer confirms this.

use proptest::prelude::*;
use seismic_revm::precompiles::{
    aes::{aes_gcm_dec::precompile_decrypt, aes_gcm_enc::precompile_encrypt},
    ecdh_derive_sym_key::derive_symmetric_key,
    hkdf_derive_sym_key::hkdf_derive_symmetric_key,
    secp256k1_sign::secp256k1_sign_ecdsa_recoverable,
};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        .. ProptestConfig::default()
    })]

    // -----------------------------------------------------------------------
    // AES-GCM Encryption precompile (address 102)
    //
    // Has `.expect("must be 12 bytes")` at aes_gcm_enc.rs:69 — theoretically
    // guarded by validate_nonce_length, but we confirm via fuzzing.
    // -----------------------------------------------------------------------

    #[test]
    fn precompile_aes_encrypt_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
        gas_limit in any::<u64>()
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = precompile_encrypt(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in AES encrypt precompile — security bug");
    }

    // -----------------------------------------------------------------------
    // AES-GCM Decryption precompile (address 103)
    //
    // Has `.expect("must be 12 bytes")` at aes_gcm_dec.rs:53
    // -----------------------------------------------------------------------

    #[test]
    fn precompile_aes_decrypt_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
        gas_limit in any::<u64>()
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = precompile_decrypt(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in AES decrypt precompile — security bug");
    }

    // -----------------------------------------------------------------------
    // ECDH key derivation precompile (address 101)
    //
    // Has `.expect("must be 32 bytes")` in derive_symmetric_key
    // Expected input: 32B secret key + 33B compressed public key = 65B
    // -----------------------------------------------------------------------

    #[test]
    fn precompile_ecdh_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        gas_limit in any::<u64>()
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = derive_symmetric_key(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in ECDH precompile — security bug");
    }

    // -----------------------------------------------------------------------
    // HKDF key derivation precompile (address 104)
    //
    // Variable length input, no minimum
    // -----------------------------------------------------------------------

    #[test]
    fn precompile_hkdf_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
        gas_limit in any::<u64>()
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = hkdf_derive_symmetric_key(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in HKDF precompile — security bug");
    }

    // -----------------------------------------------------------------------
    // secp256k1 sign precompile (address 105)
    //
    // Expected input: 32B secret key + 32B message = 64B
    // Has .try_into().unwrap() at secp256k1_sign.rs:47-48, guarded by length check
    // -----------------------------------------------------------------------

    #[test]
    fn precompile_secp256k1_sign_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        gas_limit in any::<u64>()
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = secp256k1_sign_ecdsa_recoverable(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in secp256k1_sign precompile — security bug");
    }

    // -----------------------------------------------------------------------
    // Targeted edge cases: inputs near expected boundaries
    // -----------------------------------------------------------------------

    /// AES encrypt: inputs around the 44-byte minimum boundary
    #[test]
    fn precompile_aes_encrypt_boundary_inputs(
        data in proptest::collection::vec(any::<u8>(), 40..50),
        gas_limit in 0u64..10_000
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = precompile_encrypt(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in AES encrypt boundary test — security bug");
    }

    /// AES decrypt: inputs around the 60-byte minimum boundary
    #[test]
    fn precompile_aes_decrypt_boundary_inputs(
        data in proptest::collection::vec(any::<u8>(), 56..66),
        gas_limit in 0u64..10_000
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = precompile_decrypt(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in AES decrypt boundary test — security bug");
    }

    /// ECDH: inputs around the 65-byte expected length
    #[test]
    fn precompile_ecdh_boundary_inputs(
        data in proptest::collection::vec(any::<u8>(), 60..70),
        gas_limit in 0u64..10_000
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = derive_symmetric_key(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in ECDH boundary test — security bug");
    }

    /// secp256k1_sign: inputs around the 64-byte expected length
    #[test]
    fn precompile_secp256k1_sign_boundary_inputs(
        data in proptest::collection::vec(any::<u8>(), 60..70),
        gas_limit in 0u64..10_000
    ) {
        let result = std::panic::catch_unwind(|| {
            let _ = secp256k1_sign_ecdsa_recoverable(&data, gas_limit);
        });
        prop_assert!(result.is_ok(), "PANIC in secp256k1_sign boundary test — security bug");
    }
}
