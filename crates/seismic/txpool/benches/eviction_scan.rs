//! Benchmarks the per-head freshness-eviction scan (`stale_seismic_hashes`) over pool sizes.
//!
//! Measures the steady-state cost: a fully-populated cache and fresh txs, so the scan walks every
//! tx, does the full freshness check, and evicts nothing — the work paid on every block.
#![allow(missing_docs)]

use alloy_consensus::transaction::Recovered;
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use reth_seismic_test_utils::get_signed_seismic_tx;
use reth_seismic_txpool::{stale_seismic_hashes, RecentBlockCache, SeismicPooledTransaction};
use reth_transaction_pool::{
    identifier::{SenderId, TransactionId},
    TransactionOrigin, ValidPoolTransaction,
};
use std::{sync::Arc, time::Instant};

fn make_tx(recent_block_hash: B256) -> Arc<ValidPoolTransaction<SeismicPooledTransaction>> {
    let recovered =
        Recovered::new_unchecked(get_signed_seismic_tx(recent_block_hash), Address::ZERO);
    let len = recovered.encode_2718_len();
    Arc::new(ValidPoolTransaction {
        transaction: SeismicPooledTransaction::new(recovered, len),
        transaction_id: TransactionId::new(SenderId::from(1u64), 1),
        propagate: true,
        timestamp: Instant::now(),
        origin: TransactionOrigin::External,
        authority_ids: None,
    })
}

fn bench_scan(c: &mut Criterion) {
    let hash = B256::repeat_byte(7);

    // Complete cache containing the tx's recent_block_hash, tip at block 100. The tx expires at
    // 1_000_000 (helper default), so nothing is evicted -> the full per-tx path is exercised.
    let mut cache = RecentBlockCache::new(100);
    cache.rebuild(std::iter::once((hash, 100)));
    let tx = make_tx(hash);

    let mut group = c.benchmark_group("stale_seismic_scan");
    for n in [100usize, 1_000, 10_000, 50_000] {
        let txs: Vec<_> = std::iter::repeat_with(|| tx.clone()).take(n).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &txs, |b, txs| {
            b.iter(|| stale_seismic_hashes(txs.iter(), &cache));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
