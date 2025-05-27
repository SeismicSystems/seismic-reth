//! Utils for testing the seismic rpc api

use alloy_rpc_types::TransactionRequest;
use reth_primitives::Recovered;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_eth_types::{EthApiError, EthResult};
use seismic_alloy_consensus::TypedDataRequest;
use seismic_alloy_rpc_types::SeismicTransactionRequest;
use seismic_alloy_rpc_types::SeismicCallRequest;
use reth_rpc_eth_types::utils::recover_raw_transaction;
use seismic_alloy_consensus::SeismicTxEnvelope;
use seismic_alloy_consensus::Decodable712;

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
pub fn recover_typed_data_request<T: SignedTransaction>(
    mut data: &TypedDataRequest,
) -> EthResult<Recovered<T>> {
    let transaction =
        T::decode_712(&mut data).map_err(|_| EthApiError::FailedToDecodeSignedTransaction)?;

    transaction.try_into_recovered().or(Err(EthApiError::InvalidTransactionSignature))
}

/// Convert a [`SeismicCallRequest`] to a [`SeismicTransactionRequest`].
/// 
/// If the call requests simulates a transaction without a signature from msg.sender,
/// we null out the fields that may reveal sensitive information.
pub fn convert_seismic_call_to_tx_request(request: SeismicCallRequest) -> Result<SeismicTransactionRequest, EthApiError> {
    match request {
        SeismicCallRequest::TransactionRequest(mut tx_request) => {
            seismic_override_call_request(&mut tx_request.inner); // null fields that may reveal sensitive information
            Ok(tx_request)
        }

        SeismicCallRequest::TypedData(typed_request) => {
            SeismicTransactionRequest::decode_712(&typed_request).map_err(
                |_e| EthApiError::FailedToDecodeSignedTransaction,
            )
        }

        SeismicCallRequest::Bytes(bytes) => {
            let tx = recover_raw_transaction::<SeismicTxEnvelope>(&bytes)?;
            Ok(tx.inner().clone().into())
        }
    }
}