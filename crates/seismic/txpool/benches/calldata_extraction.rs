#![allow(missing_docs)]

use alloy_primitives::{Address, Bytes, U256};
use criterion::{criterion_group, criterion_main, Criterion};
use reth_seismic_txpool::screening::extract_calldata_addresses;
use std::hint::black_box;

// ──── Selector constants ───────────────────────────────────────────────────
const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const SAFE_TRANSFER_FROM: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e];
const SAFE_TRANSFER_FROM_DATA: [u8; 4] = [0xb8, 0x8d, 0x4f, 0xde];
const ERC1155_SAFE_TRANSFER_FROM: [u8; 4] = [0xf2, 0x42, 0x43, 0x2a];
const ERC1155_SAFE_BATCH_TRANSFER_FROM: [u8; 4] = [0x2e, 0xb2, 0xc2, 0xd6];

// ──── Helpers ──────────────────────────────────────────────────────────────

fn encode_address_word(addr: Address) -> Vec<u8> {
    let mut word = vec![0u8; 12];
    word.extend_from_slice(addr.as_slice());
    word
}

fn encode_uint256_word(val: U256) -> Vec<u8> {
    val.to_be_bytes::<32>().to_vec()
}

fn encode_call(selector: [u8; 4], addresses: &[Address], extra_words: usize) -> Bytes {
    let mut data = Vec::with_capacity(4 + (addresses.len() + extra_words) * 32);
    data.extend_from_slice(&selector);
    for addr in addresses {
        data.extend_from_slice(&encode_address_word(*addr));
    }
    for _ in 0..extra_words {
        data.extend_from_slice(&encode_uint256_word(U256::ZERO));
    }
    Bytes::from(data)
}

// ──── Benchmarks ───────────────────────────────────────────────────────────

fn bench_calldata_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("Calldata address extraction");

    group.bench_function("erc20_transfer", |b| {
        let input = encode_call(TRANSFER, &[Address::random()], 1);
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("erc20_transferFrom", |b| {
        let input = encode_call(TRANSFER_FROM, &[Address::random(), Address::random()], 1);
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("erc721_safeTransferFrom", |b| {
        let input = encode_call(SAFE_TRANSFER_FROM, &[Address::random(), Address::random()], 1);
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("erc721_safeTransferFrom_with_data", |b| {
        let input =
            encode_call(SAFE_TRANSFER_FROM_DATA, &[Address::random(), Address::random()], 2);
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("erc1155_safeTransferFrom", |b| {
        let input =
            encode_call(ERC1155_SAFE_TRANSFER_FROM, &[Address::random(), Address::random()], 3);
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("erc1155_safeBatchTransferFrom", |b| {
        let input = encode_call(
            ERC1155_SAFE_BATCH_TRANSFER_FROM,
            &[Address::random(), Address::random()],
            3,
        );
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("unknown_selector_4kb", |b| {
        let mut data = vec![0xde, 0xad, 0xbe, 0xef];
        data.extend(std::iter::repeat_n(0u8, 4096));
        let input = Bytes::from(data);
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.bench_function("empty_input", |b| {
        let input = Bytes::new();
        b.iter(|| {
            let mut addrs = Vec::new();
            extract_calldata_addresses(black_box(&input), &mut addrs);
            addrs
        });
    });

    group.finish();
}

criterion_group! {
    name = calldata;
    config = Criterion::default();
    targets = bench_calldata_extraction
}
criterion_main!(calldata);
