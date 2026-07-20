//! Structured transaction generator for fuzz targets.
//!
//! Provides `Arbitrary`-derivable input types that convert to
//! `SeismicTransaction<TxEnv>` for EVM execution fuzzing.

use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use arbitrary::Arbitrary;
use revm::context::TxEnv;
use seismic_revm::transaction::abstraction::SeismicTransaction;

use crate::mock_state::FUZZ_CHAIN_ID;

/// Fields are bounded to prevent trivial rejections (e.g. gas too low)
/// while still allowing the fuzzer to explore interesting states.
#[derive(Arbitrary, Debug, Clone)]
/// Fuzzer input that produces well-typed `SeismicTransaction<TxEnv>`.
pub struct FuzzSeismicTx {
    /// The caller address.
    pub caller: [u8; 20],
    /// Whether to create a new contract.
    pub to_create: bool,
    /// The to address.
    pub to_address: [u8; 20],
    /// The value in wei.
    pub value_low: u64,
    /// The data.
    pub data: Vec<u8>,
    /// The gas limit.
    pub gas_limit: u32,
    /// The gas price.
    pub gas_price: u32,
    /// The nonce.
    pub nonce: u64,
    /// The tx type selector.
    pub tx_type_selector: u8,
    /// Whether to use execution mode for RNG.
    pub rng_mode_execution: bool,
    /// Number of blob hashes (0-6) for EIP-4844 txs.
    pub blob_hash_count: u8,
    /// Seed for generating blob hash bytes.
    pub blob_hash_seed: [u8; 32],
    /// Max fee per blob gas for EIP-4844 txs.
    pub max_fee_per_blob_gas: u32,
}

impl FuzzSeismicTx {
    /// Converts the fuzzer input into a `SeismicTransaction<TxEnv>`.
    pub fn into_seismic_tx(self) -> SeismicTransaction<TxEnv> {
        let kind = if self.to_create {
            TxKind::Create
        } else {
            TxKind::Call(Address::from(self.to_address))
        };

        // 0=Legacy, 1=EIP-2930, 2=EIP-1559, 3=EIP-4844, 4=Seismic (0x4A)
        let tx_type = match self.tx_type_selector % 5 {
            0 => 0u8,
            1 => 1,
            2 => 2,
            3 => 3,
            _ => 0x4A,
        };

        // Populate blob fields when tx_type is EIP-4844
        let (blob_hashes, max_fee_per_blob_gas) = if tx_type == 3 {
            let count = (self.blob_hash_count % 7).max(1) as usize; // 1-6 blobs
            let hashes: Vec<B256> = (0..count)
                .map(|i| {
                    let mut hash = self.blob_hash_seed;
                    hash[0] = i as u8; // vary each hash
                    B256::from(hash)
                })
                .collect();
            (hashes, self.max_fee_per_blob_gas as u128)
        } else {
            (Vec::new(), 0)
        };

        SeismicTransaction {
            base: TxEnv {
                caller: Address::from(self.caller),
                gas_limit: (self.gas_limit as u64).max(21_000),
                gas_price: self.gas_price as u128,
                gas_priority_fee: None,
                kind,
                value: U256::from(self.value_low),
                data: Bytes::from(self.data),
                chain_id: Some(FUZZ_CHAIN_ID),
                nonce: self.nonce,
                access_list: Default::default(),
                blob_hashes,
                max_fee_per_blob_gas,
                authorization_list: Default::default(),
                tx_type,
            },
            tx_hash: Default::default(),
            decryption_failed: false,
        }
    }

    /// Forces `tx_type` to non-seismic (Legacy/EIP-2930/EIP-1559/EIP-4844) for differential
    /// testing.
    pub fn into_eth_compatible_tx(mut self) -> SeismicTransaction<TxEnv> {
        self.tx_type_selector %= 4;
        self.into_seismic_tx()
    }
}
