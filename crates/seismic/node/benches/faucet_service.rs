//! Faucet service for sending ETH to wallets
use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_rpc_types::{Block, Header, Transaction, TransactionReceipt};
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::http_client::HttpClient;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_rpc_eth_api::EthApiClient;
use seismic_node::utils::test_utils::{
    get_nonce, get_signed_seismic_tx_bytes, get_unsigned_seismic_tx_request,
};
use std::{collections::VecDeque, sync::Arc, thread, time::Duration, sync::atomic::{AtomicU64, Ordering}};
use tokio::sync::Mutex;

/// Request to send ETH to a wallet
pub(crate) struct FaucetRequest {
    pub target_wallet: Address,
    pub amount: U256,
}

/// Faucet service
pub(crate) struct FaucetService {
    faucet_signer: Arc<PrivateKeySigner>,
    from: Address,
    requests: Arc<Mutex<VecDeque<FaucetRequest>>>,
    client: HttpClient,
    chain_id: u64,
}

impl FaucetService {
    /// Create a new faucet service
    pub(crate) async fn new(
        faucet_wallet: Arc<PrivateKeySigner>,
        rpc_url: &str,
        chain_id: u64,
        from: Address,
    ) -> Self {
        let client = jsonrpsee::http_client::HttpClientBuilder::default().build(rpc_url).unwrap();
        
        Self {
            faucet_signer: faucet_wallet,
            from,
            requests: Arc::new(Mutex::new(VecDeque::new())),
            client,
            chain_id,
        }
    }

    /// Add a new request to the faucet service
    pub(crate) async fn add_request(&self, target_wallet: Address, amount: U256) {
        let request = FaucetRequest { target_wallet, amount };
        let mut requests = self.requests.lock().await;
        requests.push_back(request);
    }

    /// Process all pending requests
    pub(crate) async fn process_requests(&self) -> Result<(), String> {
        let mut requests = self.requests.lock().await;
        let mut pending_txs = Vec::new();

        // Get the latest nonce at the start of processing
        let initial_nonce = get_nonce(&self.client, self.from).await;
        println!("Current nonce for faucet service: {}", initial_nonce);
        
        // Collect all requests to process concurrently
        let request_vec: Vec<FaucetRequest> = requests.drain(..).collect();
        
        // Create futures for all transactions
        let futures = request_vec.into_iter().enumerate().map(|(i, request)| {
            let faucet_signer = self.faucet_signer.clone();
            let chain_id = self.chain_id;
            let client = self.client.clone();
            
            // Calculate nonce directly from initial value plus index
            let tx_nonce = initial_nonce + i as u64;
            
            async move {
                // Construct and sign the transaction with the calculated nonce
                let tx = get_unsigned_seismic_tx_request(
                    &faucet_signer,
                    tx_nonce,
                    TxKind::Call(request.target_wallet),
                    chain_id,
                    Bytes::new(),
                )
                .await
                .with_value(request.amount);

                let signed = TransactionTestContext::sign_tx(faucet_signer.as_ref().clone(), tx).await;
                let raw_tx: Bytes = <TxEnvelope as Encodable2718>::encoded_2718(&signed).into();

                // Send the raw transaction
                match EthApiClient::<Transaction, Block, TransactionReceipt, Header>::send_raw_transaction(
                    &client,
                    raw_tx.into(),
                )
                .await {
                    Ok(tx_hash) => {
                        let mut receipt: Option<TransactionReceipt> = None;
                        for _ in 0..10 {
                            // Try up to 10 times with 1 second delay
                            thread::sleep(Duration::from_secs(1));
                            println!("retry with transaction hash: {:?}", tx_hash);

                            match EthApiClient::<Transaction, Block, TransactionReceipt, Header>::transaction_receipt(
                                &client, tx_hash,
                            ).await {
                                Ok(Some(r)) => {
                                    receipt = Some(r);
                                    break;
                                }
                                _ => continue,
                            }
                        }

                        // Check if the transaction was successful
                        if let Some(r) = receipt {
                            if !r.status() {
                                return Err((request, format!("Transaction failed: {:?}", tx_hash)));
                            }
                            Ok((tx_hash, request))
                        } else {
                            Err((request, format!("Couldn't get receipt for transaction: {:?}", tx_hash)))
                        }
                    }
                    Err(e) => Err((request, e.to_string())),
                }
            }
        });

        // Execute all futures concurrently
        let results = futures::future::join_all(futures).await;
        
        // Process results
        for result in results {
            match result {
                Ok((tx_hash, request)) => {
                    pending_txs.push((tx_hash, request));
                }
                Err((request, error)) => {
                    return Err(error);
                }
            }

        }
        println!("Sent {} transactions to increase eth balance", pending_txs.len());

        Ok(())
    }
}
