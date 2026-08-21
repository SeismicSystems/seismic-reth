//! Utils for testing the seismic rpc api

use alloy_primitives::{Address, B256};
use reth_primitives::Recovered;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_eth_types::{EthApiError, EthResult};
use reth_seismic_primitives::{
    transaction::error::SeismicTxError, SEISMIC_TX_RECENT_BLOCK_LOOKBACK,
};
use reth_storage_api::BlockNumReader;
use seismic_alloy_consensus::{
    Decodable712, SeismicTxEnvelope, TxSeismicElements, TypedDataRequest,
};
use seismic_alloy_network::{SeismicReth, TransactionBuilder};
use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicTransactionRequest};

use crate::ext::ext_decryption_error;
use alloy_seismic_evm::secp256k1::SecretKey;
use seismic_alloy_consensus::InputDecryptionElements;

/// Override the request for seismic calls
pub const fn seismic_override_call_request(request: &mut SeismicTransactionRequest) {
    // If user calls with the standard (unsigned) eth_call,
    // then disregard whatever they put in the from field
    // They will still be able to read public contract functions,
    // but they will not be able to spoof msg.sender in these calls
    request.inner.from = None;
    request.inner.gas_price = None; // preventing InsufficientFunds error
    request.inner.max_fee_per_gas = None; // preventing InsufficientFunds error
    request.inner.max_priority_fee_per_gas = None; // preventing InsufficientFunds error
    request.inner.max_fee_per_blob_gas = None; // preventing InsufficientFunds error
    request.inner.value = None; // preventing InsufficientFunds error
    request.seismic_elements = None; // zero out seismic elements
}

/// Recovers a [`SignedTransaction`] from a typed data request.
///
/// This is a helper function that returns the appropriate RPC-specific error if the input data is
/// malformed.
///
/// See [`alloy_eips::eip2718::Decodable2718::decode_2718`]
pub fn recover_typed_data_request<T: SignedTransaction + Decodable712>(
    data: &TypedDataRequest,
) -> EthResult<Recovered<T>> {
    let transaction =
        T::decode_712(data).map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;

    SignedTransaction::try_into_recovered(transaction)
        .or(Err(EthApiError::InvalidTransactionSignature))
}

/// A resolved Seismic call, classified by its authenticated execution semantics.
#[derive(Clone, Debug)]
pub enum SeismicCall {
    /// An unsigned object-form request. Sender-sensitive fields have been sanitized.
    Transparent(SeismicTransactionRequest),
    /// A signed, call-only request whose `signed_read` intent is covered by its signature.
    SignedRead(SeismicTransactionRequest),
}

/// Resolve a wire-format [`SeismicCallRequest`] into a [`SeismicCall`].
///
/// Unsigned object-form requests are sanitized. Signed typed-data and raw-byte requests must carry
/// an authenticated `signed_read = true` intent so mempool-admissible write transactions cannot be
/// replayed through simulation RPCs.
pub fn resolve_seismic_call(request: SeismicCallRequest) -> Result<SeismicCall, EthApiError> {
    match request {
        SeismicCallRequest::TransactionRequest(mut tx_request) => {
            seismic_override_call_request(&mut tx_request); // null fields that may reveal sensitive information
            Ok(SeismicCall::Transparent(tx_request))
        }

        SeismicCallRequest::TypedData(typed_request) => {
            // TODO(samlaf): this arm exists because `SeismicCallRequest::TypedData` is redundant
            // with the `Bytes` variant below — clients could submit the same
            // EIP-712-signed payload as RLP bytes (with `message_version = 2`).
            // Once we have updated our clients and are sure no one is submitting via this path,
            // we can delete this arm and the `TypedData` variant entirely.
            let req = SeismicTransactionRequest::decode_712(&typed_request)
                .map_err(|_e| EthApiError::FailedToDecodeSignedTransaction)?;
            // Bound the calldata before the downstream ECDH/AES decrypt — same limit as the bytes
            // path, so the guard can't be bypassed by submitting via TypedData instead of Bytes.
            check_signed_read_input_size(req.inner.input.input().map_or(0, |b| b.len()))?;
            ensure_signed_read_request(&req)?;
            Ok(SeismicCall::SignedRead(req))
        }

        SeismicCallRequest::Bytes(bytes) => {
            let tx = recover_raw_seismic_call_tx(&bytes)?;
            let mut req: SeismicTransactionRequest = tx.inner().clone().into();
            TransactionBuilder::<SeismicReth>::set_from(&mut req, tx.signer());
            ensure_signed_read_request(&req)?;
            Ok(SeismicCall::SignedRead(req))
        }
    }
}

/// Ensure a signed simulation request is authenticated and explicitly call-only.
fn ensure_signed_read_request(request: &SeismicTransactionRequest) -> Result<(), EthApiError> {
    parse_request_sender(request)?;

    let elements = request.seismic_elements.as_ref().ok_or_else(|| {
        EthApiError::InvalidParams("signed read missing seismic_elements".to_string())
    })?;
    if !elements.signed_read {
        return Err(EthApiError::InvalidParams(
            "signed simulation request must set signedRead=true".to_string(),
        ));
    }

    Ok(())
}

/// Reject a signed read whose payload exceeds the configured size cap, before any of the unmetered
/// decrypt crypto (decode, keccak sighash, secp256k1 recovery, ECDH, AES-GCM) runs.
///
/// A signed read is a transaction that skips the mempool, so we hold it to the same per-tx size
/// limit real transactions obey (`--seismic.rpc.max-signed-read-input-bytes`, default
/// `DEFAULT_MAX_TX_INPUT_BYTES`). Both submission paths gate on this so the bound can't be bypassed
/// by choosing one format over the other: `len` is the raw tx size on the bytes path, the calldata
/// size on the typed-data path.
fn check_signed_read_input_size(len: usize) -> Result<(), EthApiError> {
    let max = reth_node_core::args::seismic_rpc_args().max_signed_read_input_bytes;
    if len > max {
        return Err(EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
            -32602,
            format!("signed-read payload exceeds {max} bytes (got {len})"),
            None::<String>,
        ))));
    }
    Ok(())
}

/// Decode a raw EIP-2718 transaction submitted via the `eth_call` bytes path
/// and recover its signer.
///
/// This is the `eth_call` counterpart of
/// [`reth_rpc_eth_types::utils::recover_raw_transaction`]. It uses
/// [`SeismicTxEnvelope::decode_2718_permit_seismic_calls`] so that signed
/// seismic read requests (`signed_read = true`) are accepted. Those payloads
/// are rejected on block / mempool / p2p / `eth_sendRawTransaction` paths to
/// prevent replay as state-changing transactions.
fn recover_raw_seismic_call_tx(data: &[u8]) -> EthResult<Recovered<SeismicTxEnvelope>> {
    if data.is_empty() {
        return Err(EthApiError::EmptyRawTransactionData);
    }
    // Bound the raw tx size before any decode/recover/decrypt crypto runs.
    check_signed_read_input_size(data.len())?;
    let mut buf: &[u8] = data;
    let transaction = SeismicTxEnvelope::decode_2718_permit_seismic_calls(&mut buf)
        .map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;
    SignedTransaction::try_into_recovered(transaction)
        .or(Err(EthApiError::InvalidTransactionSignature))
}

/// Get the sender address from a seismic transaction request.
/// Returns an error if the sender is missing.
pub fn parse_request_sender(request: &SeismicTransactionRequest) -> Result<Address, EthApiError> {
    request.inner.from.ok_or_else(|| {
        EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
            -32602,
            "Missing 'from' field for seismic transaction",
            None::<String>,
        )))
    })
}

/// Convert a resolved Seismic call into the plaintext transaction request executed by the EVM.
///
/// Transparent calls are already plaintext. Signed reads have their freshness fields validated
/// before their calldata is decrypted with the node's secret key.
pub fn seismic_call_to_plaintext_tx<P>(
    call: &SeismicCall,
    secret_key: &SecretKey,
    provider: &P,
) -> Result<SeismicTransactionRequest, EthApiError>
where
    P: BlockNumReader,
{
    match call {
        SeismicCall::Transparent(request) => Ok(request.clone()),
        SeismicCall::SignedRead(request) => {
            // Keep this defensive check even though `resolve_seismic_call` establishes the enum's
            // invariant, so direct construction cannot silently skip freshness validation.
            let elements = request.seismic_elements.as_ref().ok_or_else(|| {
                EthApiError::InvalidParams("signed read missing seismic_elements".to_string())
            })?;
            // Reject stale or expired signed reads before doing any ECDH work.
            validate_seismic_freshness(elements, provider)?;

            let sender = parse_request_sender(request)?;
            request
                .plaintext_copy(secret_key, sender)
                .map_err(|e| ext_decryption_error(e.to_string()))
        }
    }
}

/// Validate the freshness fields of a signed seismic read against the live chain tip.
///
/// Enforces two invariants:
/// 1. `expires_at_block` is not in the past relative to the canonical chain tip.
/// 2. `recent_block_hash` is one of the last `SEISMIC_TX_RECENT_BLOCK_LOOKBACK` canonical block
///    hashes.
pub fn validate_seismic_freshness<P>(
    elements: &TxSeismicElements,
    provider: &P,
) -> Result<(), EthApiError>
where
    P: BlockNumReader,
{
    let current = provider.best_block_number().map_err(EthApiError::from)?;

    if current > elements.expires_at_block {
        return Err(seismic_expired_error(current, elements.expires_at_block));
    }

    let block_num = provider
        .block_number(elements.recent_block_hash)
        .map_err(EthApiError::from)?
        .ok_or_else(|| seismic_recent_block_hash_error(elements.recent_block_hash))?;

    // Verify the hash sits on the canonical chain at that height (guards against forked-out
    // hashes that the node may still have in storage).
    let canonical = provider.block_hash(block_num).map_err(EthApiError::from)?;
    if canonical != Some(elements.recent_block_hash) {
        return Err(seismic_recent_block_hash_error(elements.recent_block_hash));
    }

    if current.saturating_sub(block_num) > SEISMIC_TX_RECENT_BLOCK_LOOKBACK {
        return Err(seismic_recent_block_hash_error(elements.recent_block_hash));
    }

    Ok(())
}

/// Build a JSON-RPC error for a signed read whose `expires_at_block` has passed.
fn seismic_expired_error(current_block: u64, expires_at_block: u64) -> EthApiError {
    let err = SeismicTxError::TransactionExpired { current_block, expires_at_block };
    EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
        crate::eth::error_codes::TRANSACTION_EXPIRED,
        err.to_string(),
        None::<String>,
    )))
}

/// Build a JSON-RPC error for a signed read whose `recent_block_hash` is missing from the
/// last `SEISMIC_TX_RECENT_BLOCK_LOOKBACK` canonical blocks.
fn seismic_recent_block_hash_error(hash: B256) -> EthApiError {
    let err = SeismicTxError::RecentBlockHashNotFound {
        hash,
        lookback: SEISMIC_TX_RECENT_BLOCK_LOOKBACK,
    };
    EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
        crate::eth::error_codes::RECENT_BLOCK_HASH_NOT_FOUND,
        err.to_string(),
        None::<String>,
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod test {
    use crate::utils::{
        recover_typed_data_request, resolve_seismic_call, seismic_override_call_request,
        SeismicCall,
    };
    use alloy_consensus::SignableTransaction;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{
        aliases::U96,
        hex::{self, FromHex},
        Address, Bytes, FixedBytes, Signature, B256, U256,
    };
    use alloy_rpc_types::TransactionRequest;
    use reth_primitives_traits::SignedTransaction;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use reth_seismic_test_utils::{get_seismic_tx, get_signing_private_key, sign_seismic_tx};
    use secp256k1::PublicKey;
    use seismic_alloy_consensus::{
        SeismicTxEnvelope, TxSeismic, TxSeismicElements, TypedDataRequest,
    };
    use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicTransactionRequest};
    use std::str::FromStr;

    fn dummy_seismic_elements() -> TxSeismicElements {
        TxSeismicElements {
            encryption_pubkey: PublicKey::from_str(
                "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
            )
            .unwrap(),
            encryption_nonce: U96::from_str("0x7da3a99bf0f90d56551d99ea").unwrap(),
            message_version: 2,
            recent_block_hash: B256::ZERO,
            expires_at_block: 1,
            signed_read: false,
        }
    }

    fn spoofed_request(seismic_elements: Option<TxSeismicElements>) -> SeismicTransactionRequest {
        let victim = Address::from([0xaa; 20]);
        SeismicTransactionRequest {
            inner: TransactionRequest {
                from: Some(victim),
                nonce: Some(7),
                gas_price: Some(100),
                max_fee_per_gas: Some(200),
                max_priority_fee_per_gas: Some(50),
                max_fee_per_blob_gas: Some(10),
                value: Some(U256::from(1_000u64)),
                ..Default::default()
            },
            seismic_elements,
        }
    }

    fn assert_sanitized(req: &SeismicTransactionRequest) {
        assert_eq!(req.inner.from, None, "from must be cleared");
        assert_eq!(req.inner.gas_price, None);
        assert_eq!(req.inner.max_fee_per_gas, None);
        assert_eq!(req.inner.max_priority_fee_per_gas, None);
        assert_eq!(req.inner.max_fee_per_blob_gas, None);
        assert_eq!(req.inner.value, None);
        assert!(req.seismic_elements.is_none());
    }

    fn signed_seismic_request(signed_read: bool, typed_data: bool) -> SeismicCallRequest {
        let signing_key = get_signing_private_key();
        let sender = Address::from_public_key(signing_key.verifying_key());
        let mut tx = get_seismic_tx(sender, B256::ZERO);
        tx.seismic_elements.signed_read = signed_read;
        if typed_data {
            tx.seismic_elements.message_version = 2;
        }
        let signature = sign_seismic_tx(&tx, &signing_key);

        if typed_data {
            SeismicCallRequest::TypedData(TypedDataRequest {
                data: tx.eip712_to_type_data(),
                signature,
            })
        } else {
            let envelope = SeismicTxEnvelope::Seismic(tx.into_signed(signature));
            SeismicCallRequest::Bytes(envelope.encoded_2718().into())
        }
    }

    #[test]
    fn seismic_override_clears_from_with_seismic_elements() {
        let mut req = spoofed_request(Some(dummy_seismic_elements()));
        seismic_override_call_request(&mut req);
        assert_sanitized(&req);
    }

    /// Regression test: a previous change gated sanitization on
    /// `seismic_elements.is_some()`. That would have let an unsigned, plain
    /// (non-seismic) `eth_call` spoof `from` and have the contract execute
    /// `CLOAD` against a slot gated on `msg.sender == victim`. The sanitizer
    /// must clear `from` unconditionally for every unsigned `TransactionRequest`.
    #[test]
    fn seismic_override_clears_from_without_seismic_elements() {
        let mut req = spoofed_request(None);
        seismic_override_call_request(&mut req);
        assert_sanitized(&req);
    }

    #[test]
    fn resolves_object_request_as_sanitized_transparent_call() {
        let mut elements = dummy_seismic_elements();
        elements.signed_read = true;
        let request = SeismicCallRequest::TransactionRequest(spoofed_request(Some(elements)));

        let call = resolve_seismic_call(request).unwrap();
        assert!(matches!(call, SeismicCall::Transparent(_)));
        if let SeismicCall::Transparent(request) = call {
            assert_sanitized(&request);
        }
    }

    #[test]
    fn resolves_signed_read_bytes() {
        let call = resolve_seismic_call(signed_seismic_request(true, false)).unwrap();
        assert!(matches!(call, SeismicCall::SignedRead(_)));
    }

    #[test]
    fn rejects_write_intent_bytes() {
        let err = resolve_seismic_call(signed_seismic_request(false, false)).unwrap_err();
        assert!(err.to_string().contains("must set signedRead=true"), "{err}");
    }

    #[test]
    fn resolves_signed_read_typed_data() {
        let call = resolve_seismic_call(signed_seismic_request(true, true)).unwrap();
        assert!(matches!(call, SeismicCall::SignedRead(_)));
    }

    #[test]
    fn rejects_write_intent_typed_data() {
        let err = resolve_seismic_call(signed_seismic_request(false, true)).unwrap_err();
        assert!(err.to_string().contains("must set signedRead=true"), "{err}");
    }

    #[test]
    fn test_typed_data_tx_hash() {
        let r_bytes =
            hex::decode("e93185920818650416b4b0cc953c48f59fd9a29af4b7e1c4b1ac4824392f9220")
                .unwrap();
        let s_bytes =
            hex::decode("79b76b064a83d423997b7234c575588f60da5d3e1e0561eff9804eb04c23789a")
                .unwrap();
        let mut r_padded = [0u8; 32];
        let mut s_padded = [0u8; 32];
        let r_start = 32 - r_bytes.len();
        let s_start = 32 - s_bytes.len();

        r_padded[r_start..].copy_from_slice(&r_bytes);
        s_padded[s_start..].copy_from_slice(&s_bytes);

        let r = U256::from_be_bytes(r_padded);
        let s = U256::from_be_bytes(s_padded);

        let signature = Signature::new(r, s, false);

        let tx = TxSeismic {
            chain_id: 5124,
            nonce: 48,
            gas_price: 360000,
            gas_limit: 169477,
            to: alloy_primitives::TxKind::Call(Address::from_str("0x3aB946eEC2553114040dE82D2e18798a51cf1e14").unwrap()),
            value: U256::from_str("1000000000000000").unwrap(),
            input: Bytes::from_str("0x4e69e56c3bb999b8c98772ebb32aebcbd43b33e9e65a46333dfe6636f37f3009e93bad334235aec73bd54d11410e64eb2cab4da8").unwrap(),
            seismic_elements: TxSeismicElements {
                encryption_pubkey: PublicKey::from_str("028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0").unwrap(),
                encryption_nonce: U96::from_str("0x7da3a99bf0f90d56551d99ea").unwrap(),
                message_version: 2,
                recent_block_hash: alloy_primitives::B256::from_slice(&hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap()),
                expires_at_block: 1000000,
                signed_read: false,
            },
            authorization_list: vec![],
        };

        let signed = SeismicTransactionSigned::new_unhashed(
            seismic_alloy_consensus::SeismicTypedTransaction::Seismic(tx.clone()),
            signature,
        );
        let signed_hash = signed.recalculate_hash();
        let signed_sighash = signed.signature_hash();

        let td = tx.eip712_to_type_data();
        let req = TypedDataRequest { signature, data: td };

        let recovered = recover_typed_data_request::<SeismicTxEnvelope>(&req).unwrap();
        let recovered_hash = recovered.tx_hash();
        let recovered_sighash = recovered.signature_hash();

        let expected_tx_hash = FixedBytes::<32>::from_hex(
            "0xe82f9ce621da07a8ae10d330383275402ff9430dbe4b8b10cd0038ede3ef3718",
        )
        .unwrap();
        assert_eq!(signed_hash, expected_tx_hash);
        assert_eq!(recovered_hash, expected_tx_hash);

        let expected_sighash = FixedBytes::<32>::from_hex(
            "d84991e3c16d527e808a207b3135472c96273f93c98431ffe061de28b02555c9",
        )
        .unwrap();
        assert_eq!(signed_sighash, expected_sighash);
        assert_eq!(recovered_sighash, expected_sighash);
    }

    #[test]
    fn rejects_oversized_signed_read_payload() {
        // One byte over the cap is rejected by the size guard, before any decode/recovery crypto.
        let cap = reth_node_core::args::seismic_rpc_args().max_signed_read_input_bytes;
        let data = vec![0u8; cap + 1];
        let err = super::recover_raw_seismic_call_tx(&data).unwrap_err().to_string().to_lowercase();
        assert!(err.contains("signed-read payload exceeds"), "{err}");
    }

    #[test]
    fn at_limit_payload_passes_size_guard() {
        // Exactly at the cap clears the guard; this junk then fails to *decode*, proving the size
        // check let it through rather than rejecting on size.
        let cap = reth_node_core::args::seismic_rpc_args().max_signed_read_input_bytes;
        let data = vec![0u8; cap];
        let err = super::recover_raw_seismic_call_tx(&data).unwrap_err().to_string().to_lowercase();
        assert!(!err.contains("signed-read payload exceeds"), "{err}");
    }

    #[test]
    fn input_size_gate_rejects_over_and_passes_at_limit() {
        // The shared gate used by both submission paths (bytes via `recover_raw_seismic_call_tx`,
        // typed-data via the `convert_*` arm): at the cap is allowed, one byte over is rejected.
        let cap = reth_node_core::args::seismic_rpc_args().max_signed_read_input_bytes;
        assert!(super::check_signed_read_input_size(cap).is_ok());
        let err = super::check_signed_read_input_size(cap + 1).unwrap_err().to_string();
        assert!(err.to_lowercase().contains("signed-read payload exceeds"), "{err}");
    }

    mod freshness {
        use crate::utils::validate_seismic_freshness;
        use alloy_primitives::B256;
        use reth_seismic_primitives::SEISMIC_TX_RECENT_BLOCK_LOOKBACK;
        use reth_storage_api::{BlockHashReader, BlockNumReader};
        use reth_storage_errors::provider::{ProviderError, ProviderResult};
        use seismic_alloy_consensus::TxSeismicElements;
        use std::{collections::HashMap, sync::Mutex};

        /// Minimal in-memory provider that implements just the chain-tip / hash-lookup surface
        /// `validate_seismic_freshness` exercises.
        ///
        /// `canonical` maps `block_number` -> the canonical hash at that height.
        /// `headers` maps `block_hash` -> `block_number`, including hashes for forked-out blocks
        /// (which are intentionally absent from `canonical`).
        #[derive(Default)]
        struct MockProvider {
            canonical: Mutex<HashMap<u64, B256>>,
            headers: Mutex<HashMap<B256, u64>>,
            best: Mutex<Option<u64>>,
        }

        impl MockProvider {
            fn add_canonical(&self, num: u64, hash: B256) {
                self.canonical.lock().unwrap().insert(num, hash);
                self.headers.lock().unwrap().insert(hash, num);
                let mut best = self.best.lock().unwrap();
                *best = Some(best.map_or(num, |b| b.max(num)));
            }

            /// Add a known-but-non-canonical (forked-out) block hash at the given height.
            /// `block_number(hash)` returns `Some(num)` but `block_hash(num)` returns the
            /// canonical hash, not this one.
            fn add_orphan(&self, num: u64, hash: B256) {
                self.headers.lock().unwrap().insert(hash, num);
            }

            fn set_best(&self, num: u64) {
                *self.best.lock().unwrap() = Some(num);
            }
        }

        impl BlockHashReader for MockProvider {
            fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
                Ok(self.canonical.lock().unwrap().get(&number).copied())
            }

            fn canonical_hashes_range(&self, _: u64, _: u64) -> ProviderResult<Vec<B256>> {
                unimplemented!("not exercised by validate_seismic_freshness")
            }
        }

        impl BlockNumReader for MockProvider {
            fn chain_info(&self) -> ProviderResult<reth_chainspec::ChainInfo> {
                unimplemented!("not exercised by validate_seismic_freshness")
            }

            fn best_block_number(&self) -> ProviderResult<u64> {
                self.best.lock().unwrap().ok_or(ProviderError::BestBlockNotFound)
            }

            fn last_block_number(&self) -> ProviderResult<u64> {
                self.best_block_number()
            }

            fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
                Ok(self.headers.lock().unwrap().get(&hash).copied())
            }
        }

        fn elements(hash: B256, expires_at: u64) -> TxSeismicElements {
            TxSeismicElements {
                recent_block_hash: hash,
                expires_at_block: expires_at,
                ..Default::default()
            }
        }

        fn hash(byte: u8) -> B256 {
            B256::from([byte; 32])
        }

        #[test]
        fn passes_when_hash_is_recent_and_not_expired() {
            let provider = MockProvider::default();
            let h = hash(1);
            provider.add_canonical(50, h);
            provider.set_best(100);

            assert!(validate_seismic_freshness(&elements(h, 1_000_000), &provider).is_ok());
        }

        #[test]
        fn rejects_when_expires_at_block_is_past() {
            let provider = MockProvider::default();
            let h = hash(1);
            provider.add_canonical(100, h);

            let err =
                validate_seismic_freshness(&elements(h, 50), &provider).unwrap_err().to_string();
            assert!(err.contains("transaction expired"), "{err}");
        }

        #[test]
        fn passes_when_expires_at_block_equals_current() {
            // Check is `current > expires_at_block`; equality must pass.
            let provider = MockProvider::default();
            let h = hash(1);
            provider.add_canonical(100, h);

            assert!(validate_seismic_freshness(&elements(h, 100), &provider).is_ok());
        }

        #[test]
        fn rejects_when_expires_one_block_before_current() {
            let provider = MockProvider::default();
            let h = hash(1);
            provider.add_canonical(100, h);

            let err =
                validate_seismic_freshness(&elements(h, 99), &provider).unwrap_err().to_string();
            assert!(err.contains("transaction expired"), "{err}");
        }

        #[test]
        fn rejects_when_recent_block_hash_unknown() {
            let provider = MockProvider::default();
            provider.add_canonical(100, hash(1));

            let err = validate_seismic_freshness(&elements(hash(2), 1_000_000), &provider)
                .unwrap_err()
                .to_string();
            assert!(err.contains("recent_block_hash"), "{err}");
        }

        #[test]
        fn passes_at_lookback_boundary() {
            // Hash at exactly `best - SEISMIC_TX_RECENT_BLOCK_LOOKBACK` is still in window.
            let best = 1_000;
            let in_window = best - SEISMIC_TX_RECENT_BLOCK_LOOKBACK;
            let h = hash(1);

            let provider = MockProvider::default();
            provider.add_canonical(in_window, h);
            provider.set_best(best);

            assert!(validate_seismic_freshness(&elements(h, 1_000_000), &provider).is_ok());
        }

        #[test]
        fn rejects_one_block_past_lookback_boundary() {
            let best = 1_000;
            let too_old = best - SEISMIC_TX_RECENT_BLOCK_LOOKBACK - 1;
            let h = hash(1);

            let provider = MockProvider::default();
            provider.add_canonical(too_old, h);
            provider.set_best(best);

            let err = validate_seismic_freshness(&elements(h, 1_000_000), &provider)
                .unwrap_err()
                .to_string();
            assert!(err.contains("recent_block_hash"), "{err}");
        }

        #[test]
        fn rejects_forked_out_hash() {
            // The hash is known to the provider (block_number returns Some), but the canonical
            // hash at that height is different — i.e., this hash was reorged out.
            let provider = MockProvider::default();
            let canonical_hash = hash(1);
            let forked_hash = hash(2);
            provider.add_canonical(50, canonical_hash);
            provider.add_orphan(50, forked_hash);
            provider.set_best(100);

            let err = validate_seismic_freshness(&elements(forked_hash, 1_000_000), &provider)
                .unwrap_err()
                .to_string();
            assert!(err.contains("recent_block_hash"), "{err}");
        }

        #[test]
        fn signed_read_without_seismic_elements_is_rejected() {
            // A signed read carries its freshness fields + decryption metadata in
            // `seismic_elements`; if it's absent the request must be rejected outright rather than
            // silently skipping freshness validation and proceeding to decrypt.
            use crate::utils::{seismic_call_to_plaintext_tx, SeismicCall};
            use alloy_seismic_evm::secp256k1::SecretKey;

            let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
            // Provider is never touched: the missing-elements check fires before any lookup.
            let provider = MockProvider::default();
            let request = super::spoofed_request(None);

            let err = seismic_call_to_plaintext_tx(
                &SeismicCall::SignedRead(request),
                &secret_key,
                &provider,
            )
            .unwrap_err();
            assert!(err.to_string().contains("signed read missing seismic_elements"), "{err}");
        }
    }
}
