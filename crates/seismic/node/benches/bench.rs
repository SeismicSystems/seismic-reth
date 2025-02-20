use criterion::{criterion_group, criterion_main, Criterion};
use ethers::types::{TransactionRequest, U256};
use reth::prelude::*;
use tokio::{
    task,
    time::{sleep, Duration, Instant},
}; // If using the Reth Rust client

use alloy_provider::{
    create_seismic_provider, test_utils, Provider, SeismicSignedProvider, SendableTx,
};

const BLOCK_TIME: u64 = 2; // Simulated block time in seconds
const GAS_PER_TX: u64 = 2_000_000; // Estimated gas per transaction
const MAX_GAS: u64 = 30_000_000; // Max gas per block
const TXS_PER_ROUND: usize = (MAX_GAS / GAS_PER_TX) as usize; // Number of TXs per round
const MAX_ROUNDS: usize = 100; // Set this to the number of rounds you want

async fn send_tx(provider: &SeismicProvider, contract_addr: Address) -> Result<(), String> {
    let response = provider
        .send_transaction(test_utils::get_seismic_tx_builder(
            test_utils::ContractTestContext::get_set_number_input_plaintext(),
            TxKind::Call(contract_addr),
            provider.wallet_address(),
        ))
        .await;

    match response {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("{:?}", err)),
    }
}

async fn benchmark_round(provider: &SeismicProvider, contract_addr: Address, round: usize) {
    println!("🟢 Starting benchmark round: {}", round);

    let start_time = Instant::now();
    let mut success_count = 0;
    let mut failure_count = 0;

    let mut tasks = Vec::new();
    for _ in 0..TXS_PER_ROUND {
        let provider_clone = provider.clone();
        let contract_addr_clone = contract_addr;
        tasks.push(task::spawn(async move { send_tx(&provider_clone, contract_addr_clone).await }));
    }

    let results = futures::future::join_all(tasks).await;

    for res in results {
        match res {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(_)) | Err(_) => failure_count += 1,
        }
    }

    let duration = start_time.elapsed();
    println!(
        "🔵 Round {}: Completed {} TXs in {:?}. Success: {}, Failures: {}",
        round, TXS_PER_ROUND, duration, success_count, failure_count
    );

    // Sleep to align with block time (2s per block)
    sleep(Duration::from_secs(BLOCK_TIME)).await;
}

async fn benchmark_reth(c: &mut Criterion) {
    let reth_rpc_url = SeismicRethTestCommand::url();
    let chain_id = SeismicRethTestCommand::chain_id();
    let _wallet = Wallet::default().with_chain_id(chain_id);
    let wallet = EthereumWallet::from(_wallet.inner);
    let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);

    let provider =
        create_seismic_provider(wallet.clone(), reqwest::Url::parse(&reth_rpc_url).unwrap());

    for round in 1..=MAX_ROUNDS {
        benchmark_round(&provider, contract_addr, round).await;
    }
}

criterion_group!(benches, benchmark_reth);
criterion_main!(benches);
