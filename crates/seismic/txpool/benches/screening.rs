#![allow(missing_docs)]
//! Benchmarks for ECSD address screening performance.
//!
//! **IMPORTANT**: These benchmarks require a running ECSD Docker container:
//! ```bash
//! docker run -p 9090:9090 cipherowl/ecsd:latest
//! ```

use alloy_primitives::{Address, Bytes, U256};
use criterion::{criterion_group, criterion_main, Criterion};
use reth_seismic_txpool::screening::{
    extract_calldata_addresses, ScreeningClient, ScreeningClientBuilder, ScreeningFailMode,
};
use std::{hint::black_box, time::Duration};

// ──── Helpers ──────────────────────────────────────────────────────────────

/// Default ECSD endpoint (matches CLI default)
const ECSD_ENDPOINT: &str = "http://127.0.0.1:9090";

/// Creates a screening client connected to the real ECSD Docker container
fn create_ecsd_client() -> ScreeningClient {
    ScreeningClientBuilder::new(ECSD_ENDPOINT)
        .timeout(Duration::from_secs(5))
        .fail_mode(ScreeningFailMode::Open)
        .build()
        .expect("Failed to create ECSD client. Is ECSD Docker running on port 9090?")
}

const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn random_addresses(n: usize) -> Vec<String> {
    (0..n).map(|_| format!("{:#x}", Address::random())).collect()
}

fn encode_erc20_transfer() -> Bytes {
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&TRANSFER);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(Address::random().as_slice());
    data.extend_from_slice(&U256::from(1000u64).to_be_bytes::<32>());
    Bytes::from(data)
}

// ──── Benchmarks ───────────────────────────────────────────────────────────

fn bench_screening_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Screening gRPC latency (real ECSD)");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10));

    // Create single runtime and client for all iterations
    let rt = tokio::runtime::Runtime::new().unwrap();
    let client = rt.block_on(async { create_ecsd_client() });

    for addr_count in [2, 5, 10, 50] {
        group.bench_function(format!("{addr_count}_addresses"), |b| {
            b.iter(|| {
                let addrs = random_addresses(addr_count);
                rt.block_on(async {
                    let _ = client.screen_addresses(black_box(addrs)).await;
                });
            });
        });
    }

    group.finish();
}

fn bench_screening_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Screening throughput (real ECSD)");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(15));

    // Create single runtime and client for all iterations
    let rt = tokio::runtime::Runtime::new().unwrap();
    let client = rt.block_on(async { create_ecsd_client() });

    for batch_size in [100, 500] {
        group.bench_function(format!("batch_{batch_size}_txs"), |b| {
            b.iter(|| {
                let batches: Vec<Vec<String>> =
                    (0..batch_size).map(|_| random_addresses(3)).collect();
                rt.block_on(async {
                    for addrs in batches {
                        let _ = client.screen_addresses(addrs).await;
                    }
                });
            });
        });
    }

    group.finish();
}

fn bench_screening_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Screening overhead comparison (real ECSD)");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(10));

    // Baseline: calldata extraction only (no gRPC)
    group.bench_function("extraction_only_100_txs", |b| {
        let inputs: Vec<Bytes> = (0..100).map(|_| encode_erc20_transfer()).collect();
        b.iter(|| {
            for input in &inputs {
                let mut addrs = Vec::new();
                extract_calldata_addresses(black_box(input), &mut addrs);
            }
        });
    });

    // With real ECSD screening
    group.bench_function("extraction_plus_screening_100_txs", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = rt.block_on(async { create_ecsd_client() });
        let inputs: Vec<Bytes> = (0..100).map(|_| encode_erc20_transfer()).collect();

        b.iter(|| {
            rt.block_on(async {
                for input in &inputs {
                    let mut addrs = Vec::new();
                    extract_calldata_addresses(input, &mut addrs);
                    let strs: Vec<String> = addrs.iter().map(|a| format!("{a:#x}")).collect();
                    let _ = client.screen_addresses(strs).await;
                }
            });
        });
    });

    group.finish();
}

criterion_group! {
    name = screening;
    config = Criterion::default();
    targets = bench_screening_latency, bench_screening_throughput, bench_screening_overhead
}
criterion_main!(screening);
