//! Utils for testing the seismic rpc api

use alloy_rpc_types::TransactionRequest;
use reth_primitives::Recovered;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError, EthResult};
use seismic_alloy_consensus::{Decodable712, SeismicTxEnvelope, TypedDataRequest};
use seismic_alloy_network::{SeismicReth, TransactionBuilder};
use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicTransactionRequest};

/// Override the request for seismic calls
pub fn seismic_override_call_request(request: &mut TransactionRequest) {
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
) -> Result<SeismicTransactionRequest, EthApiError> {
    match request {
        SeismicCallRequest::TransactionRequest(mut tx_request) => {
            seismic_override_call_request(&mut tx_request.inner); // null fields that may reveal sensitive information
            Ok(tx_request)
        }

        SeismicCallRequest::TypedData(typed_request) => {
            SeismicTransactionRequest::decode_712(&typed_request)
                .map_err(|_e| EthApiError::FailedToDecodeSignedTransaction)
        }

        SeismicCallRequest::Bytes(bytes) => {
            let tx = recover_raw_transaction::<SeismicTxEnvelope>(&bytes)?;
            let mut req: SeismicTransactionRequest = tx.inner().clone().into();
            TransactionBuilder::<SeismicReth>::set_from(&mut req, tx.signer());
            Ok(req)
        }
    }
}

#[cfg(test)]
mod test {
    use std::{hash::Hash, str::FromStr};

    use alloy_primitives::{aliases::U96, hex, Address, Bytes, Signature, U256};
    use reth_primitives_traits::SignedTransaction;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use secp256k1::PublicKey;
    use seismic_alloy_consensus::{
        SeismicTxEnvelope, TxSeismic, TxSeismicElements, TypedDataRequest,
    };
    use seismic_alloy_network::Seismic;

    use crate::utils::recover_typed_data_request;

    #[test]
    fn test_typed_data_tx_hash() {
        /*
        {
            "typedData": {
                "types": {
                "EIP712Domain": [
                    {
                    "name": "name",
                    "type": "string"
                    },
                    {
                    "name": "version",
                    "type": "string"
                    },
                    {
                    "name": "chainId",
                    "type": "uint256"
                    },
                    {
                    "name": "verifyingContract",
                    "type": "address"
                    }
                ],
                "TxSeismic": [
                    {
                    "name": "chainId",
                    "type": "uint64"
                    },
                    {
                    "name": "nonce",
                    "type": "uint64"
                    },
                    {
                    "name": "gasPrice",
                    "type": "uint128"
                    },
                    {
                    "name": "gasLimit",
                    "type": "uint64"
                    },
                    {
                    "name": "to",
                    "type": "address"
                    },
                    {
                    "name": "value",
                    "type": "uint256"
                    },
                    {
                    "name": "input",
                    "type": "bytes"
                    },
                    {
                    "name": "encryptionPubkey",
                    "type": "bytes"
                    },
                    {
                    "name": "encryptionNonce",
                    "type": "uint96"
                    },
                    {
                    "name": "messageVersion",
                    "type": "uint8"
                    }
                ]
                },
                "primaryType": "TxSeismic",
                "domain": {
                "name": "Seismic Transaction",
                "version": "2",
                "chainId": 5124,
                "verifyingContract": "0x0000000000000000000000000000000000000000"
                },
                "message": {
                "chainId": 5124,
                "nonce": "48",
                "gasPrice": "360000",
                "gasLimit": "169477",
                "to": "0x3aB946eEC2553114040dE82D2e18798a51cf1e14",
                "value": "1000000000000000",
                "input": "0x4e69e56c3bb999b8c98772ebb32aebcbd43b33e9e65a46333dfe6636f37f3009e93bad334235aec73bd54d11410e64eb2cab4da8",
                "encryptionPubkey": "0x028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
                "encryptionNonce": "0x7da3a99bf0f90d56551d99ea",
                "messageVersion": 2
                }
            },
            "signature": {
                "r": "0xe93185920818650416b4b0cc953c48f59fd9a29af4b7e1c4b1ac4824392f9220",
                "s": "0x79b76b064a83d423997b7234c575588f60da5d3e1e0561eff9804eb04c23789a",
                "yParity": "0x0"
            }
            }
        */
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
        // println!("Req: {:#?}", req);

        let recovered = recover_typed_data_request::<SeismicTxEnvelope>(&req).unwrap();
        // println!("Recovered typed data request: {:#?}", recovered);
        let recovered_hash = recovered.tx_hash();
        let recovered_sighash = recovered.signature_hash();

        println!("Signed hash: {:?}", signed_hash);
        println!("Recovered hash: {:?}", recovered_hash);

        println!("Signed sig hash: {:?}", signed_sighash);
        println!("Recovered sig hash: {:?}", recovered_sighash);
    }
}
