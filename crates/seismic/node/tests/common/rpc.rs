//! RPC test helpers.

use alloy_primitives::Address;
use alloy_rpc_types::{Block, Header, Transaction, TransactionReceipt};
use jsonrpsee::http_client::HttpClient;
use reth_rpc_eth_api::EthApiClient;
use seismic_alloy_rpc_types::SeismicTransactionRequest;

/// Get the nonce from the client
pub(crate) async fn get_nonce(client: &HttpClient, address: Address) -> u64 {
    let nonce = EthApiClient::<
        SeismicTransactionRequest,
        Transaction,
        Block,
        TransactionReceipt,
        Header,
    >::transaction_count(client, address, None)
    .await
    .unwrap();
    nonce.wrapping_to::<u64>()
}
