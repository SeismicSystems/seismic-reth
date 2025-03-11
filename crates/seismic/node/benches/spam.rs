//! Spam benchmark for reth
use alloy_network::EthereumWallet;
use alloy_primitives::{Address, U256};
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
mod faucet_service;
use faucet_service::FaucetService;
use futures::TryFutureExt;
use k256::ecdsa::SigningKey;
use seismic_node::utils::SeismicRethTestCommand;
use std::{ops::Deref, sync::Arc};
use tokio::{sync::mpsc, time::Instant};

use alloy_provider::{build_seismic_tx, test_utils, Provider, SeismicSignedProvider, SendableTx};

use std::{
    result::Result,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

// 86400 seconds = 24 hours = 1 day
// 2 seconds per round so there are 43200 rounds in a day

// We want 30,000,000 gas per round
// Each deploy transasction costs 194,061 gas
// Each set number transasction costs 43,696 gas
// Total transaction costs 237,757 gas
// 30,000,000 / 237,757 = 126.22459331201813

// We want 100 calls to 1 send raw transaction
// 126.22459331201813 * 100 = 12622.459331201813
// There are 43200 rounds in a day
// 12622.459331201813 * 43200 = 543,288,242 calls per day

// How much eth do we need to do this?
// gas price is 1342878663 wei
// 237,757 * 1342878663 = 318,999,999,999,999 wei
// 318,999,999,999,999 wei / 10^18 = 0.0003189999999999999 eth
// 0.0003189999999999999 eth * 126 = 0.03999999999999999 eth
// 0.03999999999999999 eth * 43200 = 1727.9999999999998 eth

// each wallet needs 1727.9999999999998 eth
// 1727.9999999999998 eth / 126 = 13.714333333333333 eth

// testing params
const WALLET_COUNT: usize = 126; // 126;
const CALL_TX_RATIO: usize = 1;
const ROUND_COUNT: usize = 43200;

const MIN_WEI_PER_WALLET: usize = 6000000000000000;
const MIN_WEI_PER_FAUCET_WALLET: usize = MIN_WEI_PER_WALLET * (WALLET_COUNT + 1);

// network params
const RPC_URL: &str = "https://node-3.seismicdev.net/rpc";
const FAUCET_URL: &str = "https://faucet-3.seismicdev.net/api/claim";
const BLOCK_TIME: u64 = 2;

#[derive(Clone)]
pub struct BenchWalletContext {
    provider: SeismicSignedProvider,
    from: Address,
}

impl BenchWalletContext {
    async fn need_eth(&self) -> Result<bool, String> {
        let balance = self.provider.get_balance(self.from).await.map_err(|e| e.to_string())?;
        println!(
            "BENCH balance: {:?}, min_wei_per_faucet_wallet: {:?}",
            balance,
            U256::from(MIN_WEI_PER_FAUCET_WALLET)
        );
        Ok(balance < U256::from(MIN_WEI_PER_FAUCET_WALLET))
    }

    async fn get_eth_from_faucet(&self) -> Result<(), String> {
        while self.need_eth().await? {
            let body = serde_json::json!({
                    "address": format!("{}", self.from)
            });
            let response = reqwest::Client::new()
                .post(FAUCET_URL)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await;

            tokio::time::sleep(Duration::from_secs(BLOCK_TIME + 1)).await;
            println!("response: {:?}", response);
        }
        Ok(())
    }

    async fn new_with_pk(pk: &str) -> Self {
        let signer = LocalSigner::<SigningKey>::from_str(pk).unwrap();
        let from = signer.address();
        let provider = SeismicSignedProvider::new(
            EthereumWallet::new(signer),
            reqwest::Url::parse(RPC_URL).unwrap(),
        );

        Self { provider, from }
    }

    /// Create a new benchmark wallet context
    async fn new() -> Self {
        let signer = LocalSigner::<SigningKey>::random();
        let from = signer.address();
        let provider = SeismicSignedProvider::new(
            EthereumWallet::new(signer),
            reqwest::Url::parse(RPC_URL).unwrap(),
        );

        Self { provider, from }
    }

    async fn deploy_set_number(&self) -> Result<Address, String> {
        println!("BENCH deploy_set_number: from={:?}", self.from);
        let tx = build_seismic_tx(
            test_utils::ContractTestContext::get_deploy_input_plaintext(),
            alloy_primitives::TxKind::Create,
            self.from,
        );

        let contract_addr = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| e.to_string())?
            .get_receipt()
            .await
            .map_err(|e| e.to_string())?
            .contract_address
            .ok_or_else(|| "BENCH deploy_set_number error: deploy failed".to_string())?;

        println!("BENCH deploy_set_number: contract_addr={:?}", contract_addr);

        let tx = build_seismic_tx(
            test_utils::ContractTestContext::get_set_number_input_plaintext(),
            alloy_primitives::TxKind::Call(contract_addr),
            self.from,
        );

        println!("BENCH deploy_set_number: set_number_tx={:?}", tx);

        let receipt = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| e.to_string())?
            .get_receipt()
            .await
            .map_err(|e| e.to_string())?;

        println!("BENCH deploy_set_number: receipt={:?}", receipt);

        Ok(contract_addr)
    }

    /// Make a call to an existing contract
    async fn call(&self, contract_addr: Address) -> Result<(), String> {
        let _ = self
            .provider
            .seismic_call(SendableTx::Builder(build_seismic_tx(
                test_utils::ContractTestContext::get_is_odd_input_plaintext(),
                alloy_primitives::TxKind::Call(contract_addr),
                self.from,
            )))
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl Deref for BenchWalletContext {
    type Target = SeismicSignedProvider;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}

/// Context for running benchmark tests
struct BenchContext {
    wallets: Vec<BenchWalletContext>,
    fallback_contract_addr: Address,
    faucet_service: FaucetService,
}

/// Results from a single benchmark round
#[derive(Debug)]
struct RoundResult {
    /// Number of transaction failures  
    transaction_fail_count: usize,
    /// Number of call failures
    call_fail_count: usize,
    /// Total transaction time
    total_transaction_time: u128,
    /// Total call time
    total_call_time: u128,
}

impl BenchContext {
    /// Create a new benchmark context
    async fn new(
        wallets: Vec<BenchWalletContext>,
        fallback_contract_addr: Address,
        faucet_service: FaucetService,
    ) -> Self {
        Self { wallets, fallback_contract_addr, faucet_service }
    }

    /// Execute a single round of benchmarks
    async fn execute_round(&self) -> RoundResult {
        let transaction_fail_count = Arc::new(AtomicUsize::new(0));
        let call_fail_count = Arc::new(AtomicUsize::new(0));
        let total_transaction_time = Arc::new(AtomicUsize::new(0));
        let total_call_time = Arc::new(AtomicUsize::new(0));

        // First, check which wallets need ETH and add them to the faucet service
        for wallet_ctx in &self.wallets {
            println!("BENCH adding wallet to faucet service: {:?}", wallet_ctx.from);
            self.faucet_service.add_request(wallet_ctx.from, U256::from(MIN_WEI_PER_WALLET)).await;
        }

        // Process all requests at once
        if let Err(e) = self.faucet_service.process_requests().await {
            println!("Error processing faucet requests: {}", e);
        }

        let futures = self.wallets.iter().map(|wallet_ctx| {
            let transaction_fail_count = Arc::clone(&transaction_fail_count);
            let total_transaction_time = Arc::clone(&total_transaction_time);
            let call_fail_count = Arc::clone(&call_fail_count);
            let total_call_time = Arc::clone(&total_call_time);

            async move {
                let start_time = Instant::now();
                let contract_addr = wallet_ctx.deploy_set_number().await.unwrap_or_else(|e| {
                    println!("BENCH deploy_set_number error: {:?}", e);
                    transaction_fail_count.fetch_add(1, Ordering::SeqCst);
                    self.fallback_contract_addr
                });
                total_transaction_time
                    .fetch_add(start_time.elapsed().as_millis() as usize, Ordering::SeqCst);

                let futures = (0..CALL_TX_RATIO).map(|_| {
                    let call_fail_count = Arc::clone(&call_fail_count);
                    let total_call_time = Arc::clone(&total_call_time);

                    async move {
                        let start_time = Instant::now();
                        wallet_ctx
                            .call(contract_addr)
                            .unwrap_or_else(|e| {
                                println!("BENCH call error: {:?}", e);
                                call_fail_count.fetch_add(1, Ordering::SeqCst);
                            })
                            .await;
                        total_call_time
                            .fetch_add(start_time.elapsed().as_millis() as usize, Ordering::SeqCst);
                    }
                });
                futures::future::join_all(futures).await;
            }
        });

        futures::future::join_all(futures).await;

        RoundResult {
            transaction_fail_count: transaction_fail_count.load(Ordering::SeqCst),
            call_fail_count: call_fail_count.load(Ordering::SeqCst),
            total_transaction_time: total_transaction_time.load(Ordering::SeqCst) as u128,
            total_call_time: total_call_time.load(Ordering::SeqCst) as u128,
        }
    }
}

/// Benchmark reth node performance by executing multiple rounds of transactions and calls
async fn benchmark_reth() {
    // Setup phase - run once before benchmarking
    // let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    // let (tx, mut rx) = mpsc::channel(1);
    // SeismicRethTestCommand::run(tx, shutdown_rx).await;
    // rx.recv().await.unwrap();

    let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let faucet_wallet = BenchWalletContext::new_with_pk(pk).await;

    let faucet_signer = PrivateKeySigner::from_str(pk).unwrap();
    let chain_id = faucet_wallet.get_chain_id().await.unwrap();
    faucet_wallet.get_eth_from_faucet().await.unwrap();
    let faucet_service =
        FaucetService::new(Arc::new(faucet_signer), RPC_URL, chain_id, faucet_wallet.from).await;

    let contract_addr = faucet_wallet.deploy_set_number().await.unwrap();

    let mut wallets = Vec::with_capacity(WALLET_COUNT);

    for _ in 0..WALLET_COUNT {
        let wallet = BenchWalletContext::new().await;
        wallets.push(wallet);
    }

    let ctx = BenchContext::new(wallets, contract_addr, faucet_service).await;

    for i in 0..ROUND_COUNT {
        faucet_wallet.get_eth_from_faucet().await.unwrap();
        let result = ctx.execute_round().await;
        // Sleep for 3 seconds between rounds to allow the network to process transactions
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("round {} result: {:?}", i, result);
    }

    // shutdown_tx.send(()).await.unwrap();
}

#[tokio::main]
async fn main() {
    println!("BENCH starting");
    benchmark_reth().await;
    println!("BENCH finished");
}
