//! Spam benchmark for reth
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::LocalSigner;
use futures::TryFutureExt;
use k256::ecdsa::SigningKey;
use seismic_node::utils::SeismicRethTestCommand;
use tokio::{sync::mpsc, time::Instant}; // If using the Reth Rust client

use alloy_provider::{build_seismic_tx, test_utils, Provider, SeismicSignedProvider, SendableTx};

use std::{
    result::Result,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
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
const CALL_TX_RATIO: usize = 100;
const ROUND_COUNT: usize = 43200;

const ETH_PER_WALLET: usize = 14;

// network params
const RPC_URL: &str = "http://localhost:8545";
fn get_faucet_signer() -> LocalSigner<SigningKey> {
    let private_key: Bytes =
        Bytes::from_str("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();

    LocalSigner::from_signing_key(SigningKey::from_slice(&private_key).unwrap())
}

#[derive(Clone)]
struct BenchWalletContext {
    provider: SeismicSignedProvider,
    from: Address,
}

impl BenchWalletContext {
    /// Create a new benchmark wallet context
    async fn new_from_faucet_context(
        faucet_context: BenchWalletContext,
        initial_eth: usize,
    ) -> Self {
        let signer = LocalSigner::<SigningKey>::random();
        let from = signer.address();
        let provider = SeismicSignedProvider::new(
            EthereumWallet::new(signer),
            reqwest::Url::parse(RPC_URL).unwrap(),
        );

        let transfer_result = faucet_context.transfer_eth(from, U256::from(initial_eth)).await;

        if let Err(e) = &transfer_result {
            println!("BENCH transfer_eth error: {}", e);
        }
        let _ = transfer_result.unwrap();

        Self { provider, from }
    }

    async fn transfer_eth(&self, to: Address, amount: U256) -> Result<(), String> {
        let tx = TransactionRequest::default().with_value(amount).with_to(to).with_from(self.from);

        let tx = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| e.to_string())?
            .get_receipt()
            .await
            .map_err(|e| e.to_string())?;

        println!("BENCH transfer_eth: from={:?} to={:?} amount={:?}", self.from, to, amount);
        Ok(())
    }

    /// Deploy and initialize a new contract
    async fn deploy_set_number(&self) -> Result<Address, String> {
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

        let tx = build_seismic_tx(
            test_utils::ContractTestContext::get_set_number_input_plaintext(),
            alloy_primitives::TxKind::Call(contract_addr),
            self.from,
        );

        let receipt = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| e.to_string())?
            .get_receipt()
            .await
            .map_err(|e| e.to_string())?;

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

/// Context for running benchmark tests
struct BenchContext {
    wallets: Vec<BenchWalletContext>,
    fallback_contract_addr: Address,
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
    fn new(wallets: Vec<BenchWalletContext>, fallback_contract_addr: Address) -> Self {
        Self { wallets, fallback_contract_addr }
    }

    /// Execute a single round of benchmarks
    async fn execute_round(&self) -> RoundResult {
        let transaction_fail_count = Arc::new(AtomicUsize::new(0));
        let call_fail_count = Arc::new(AtomicUsize::new(0));
        let total_transaction_time = Arc::new(AtomicUsize::new(0));
        let total_call_time = Arc::new(AtomicUsize::new(0));

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
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let (tx, mut rx) = mpsc::channel(1);
    SeismicRethTestCommand::run(tx, shutdown_rx).await;

    rx.recv().await.unwrap();
    // Setup code that runs before each iteration
    let faucet_signer = get_faucet_signer();
    let wallet = EthereumWallet::from(faucet_signer.clone());
    let provider = SeismicSignedProvider::new(wallet, reqwest::Url::parse(RPC_URL).unwrap());
    let faucet_context = BenchWalletContext { provider, from: faucet_signer.address() };

    let contract_addr = faucet_context.deploy_set_number().await.unwrap();

    let mut wallets = Vec::with_capacity(WALLET_COUNT);

    for _ in 0..WALLET_COUNT {
        let wallet =
            BenchWalletContext::new_from_faucet_context(faucet_context.clone(), ETH_PER_WALLET)
                .await;
        wallets.push(wallet);
    }

    let ctx = BenchContext::new(wallets, contract_addr);

    for i in 0..ROUND_COUNT {
        let result = ctx.execute_round().await;
        println!("round {} result: {:?}", i, result);
    }

    shutdown_tx.send(()).await.unwrap();
}

#[tokio::main]
async fn main() {
    benchmark_reth().await;
}
