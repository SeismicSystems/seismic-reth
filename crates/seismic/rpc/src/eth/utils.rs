//! Utils for testing the seismic rpc api

use alloy_primitives::Address;
use reth_primitives::Recovered;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError, EthResult};
use seismic_alloy_consensus::{Decodable712, SeismicTxEnvelope, TypedDataRequest};
use seismic_alloy_network::{SeismicReth, TransactionBuilder};
use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicTransactionRequest};

use crate::ext::ext_decryption_error;
use seismic_alloy_consensus::InputDecryptionElements;
use seismic_enclave::secp256k1::SecretKey;

/// Override the request for seismic calls
pub fn seismic_override_call_request(request: &mut SeismicTransactionRequest) {
    // If user calls with the standard (unsigned) eth_call,
    // then disregard whatever they put in the from field
    // They will still be able to read public contract functions,
    // but they will not be able to spoof msg.sender in these calls
    request.from = None;
    request.gas_price = None; // preventing InsufficientFunds error
    request.max_fee_per_gas = None; // preventing InsufficientFunds error
    request.max_priority_fee_per_gas = None; // preventing InsufficientFunds error
    request.max_fee_per_blob_gas = None; // preventing InsufficientFunds error
    request.value = None; // preventing InsufficientFunds error
    request.seismic_elements = None; // zero out seismic elements
}

/// Recovers a [`SignedTransaction`] from a typed data request.
///
/// This is a helper function that returns the appropriate RPC-specific error if the input data is
/// malformed.
///
/// See [`alloy_eips::eip2718::Decodable2718::decode_2718`]
pub fn recover_typed_data_request<T: SignedTransaction + Decodable712>(
    mut data: &TypedDataRequest,
) -> EthResult<Recovered<T>> {
    let transaction =
        T::decode_712(&mut data).map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;

    SignedTransaction::try_into_recovered(transaction)
        .or(Err(EthApiError::InvalidTransactionSignature))
}

/// Convert a [`SeismicCallRequest`] to a [`SeismicTransactionRequest`].
///
/// If the call requests simulates a transaction without a signature from msg.sender,
/// we null out the fields that may reveal sensitive information.
pub fn convert_seismic_call_to_tx_request(
    request: SeismicCallRequest,
) -> Result<(SeismicTransactionRequest, bool), EthApiError> {
    match request {
        SeismicCallRequest::TransactionRequest(mut tx_request) => {
            seismic_override_call_request(&mut tx_request); // null fields that may reveal sensitive information
            Ok((tx_request, false))
        }

        SeismicCallRequest::TypedData(typed_request) => {
            let req = SeismicTransactionRequest::decode_712(&typed_request)
                .map_err(|_e| EthApiError::FailedToDecodeSignedTransaction)?;
            Ok((req, true))
        }

        SeismicCallRequest::Bytes(bytes) => {
            let tx = recover_raw_transaction::<SeismicTxEnvelope>(&bytes)?;
            let mut req: SeismicTransactionRequest = tx.inner().clone().into();
            TransactionBuilder::<SeismicReth>::set_from(&mut req, tx.signer());
            Ok((req, true))
        }
    }
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

/// Conditionally decrypt a seismic transaction request based on whether it's a signed read.
///
/// For non-seismic transactions (`signed_read = false`), returns the request unchanged.
/// For seismic transactions (`signed_read = true`), decrypts the request using the provided secret
/// key.
pub fn signed_read_to_plaintext_tx(
    (seismic_tx_request, signed_read): (SeismicTransactionRequest, bool),
    secret_key: &SecretKey,
) -> Result<SeismicTransactionRequest, EthApiError> {
    match signed_read {
        false => Ok(seismic_tx_request),
        true => {
            let sender = parse_request_sender(&seismic_tx_request)?;
            let seismic_tx_request = seismic_tx_request
                .plaintext_copy(secret_key, sender)
                .map_err(|e| ext_decryption_error(e.to_string()))?;
            Ok(seismic_tx_request)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::utils::recover_typed_data_request;
    use alloy_primitives::{
        aliases::U96,
        hex::{self, FromHex},
        Address, Bytes, FixedBytes, Signature, U256,
    };
    use reth_primitives_traits::SignedTransaction;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use secp256k1::PublicKey;
    use seismic_alloy_consensus::{
        SeismicTxEnvelope, TxSeismic, TxSeismicElements, TypedDataRequest,
    };
    use std::str::FromStr;

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
            }
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
            "a9c1c87a4fa27002f9487ade27b5eb77ab3c82b284bc384609572f1eb8e171dc",
        )
        .unwrap();
        assert_eq!(signed_hash, expected_tx_hash);
        assert_eq!(recovered_hash, expected_tx_hash);

        let expected_sighash = FixedBytes::<32>::from_hex(
            "74a89cf115c2813a5b811dbd946f53184fa4d3a37248224f1ff72b4ba2832c2a",
        )
        .unwrap();
        assert_eq!(signed_sighash, expected_sighash);
        assert_eq!(recovered_sighash, expected_sighash);
    }
}
