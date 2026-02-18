//! Structured transaction generator for fuzz targets.
//!
//! Provides `Arbitrary`-derivable input types that convert to
//! `SeismicTransaction<TxEnv>` for EVM execution fuzzing.

use alloy_primitives::{Address, Bytes, TxKind, U256};
use arbitrary::Arbitrary;
use revm::context::TxEnv;
use seismic_revm::transaction::abstraction::{RngMode, SeismicTransaction};

/// Structured fuzzer input that produces well-typed `SeismicTransaction<TxEnv>`.
///
/// Fields are bounded to prevent trivial rejections (e.g. gas too low)
/// while still allowing the fuzzer to explore interesting states.
#[derive(Arbitrary, Debug, Clone)]
pub struct FuzzSeismicTx {
    pub caller: [u8; 20],
    pub to_create: bool,
    pub to_address: [u8; 20],
    pub value_low: u64,
    pub data: Vec<u8>,
    pub gas_limit: u32,
    pub gas_price: u32,
    pub nonce: u64,
    pub tx_type_selector: u8,
    pub rng_mode_execution: bool,
}

impl FuzzSeismicTx {
    /// Convert to a `SeismicTransaction<TxEnv>` suitable for EVM execution.
    pub fn into_seismic_tx(self) -> SeismicTransaction<TxEnv> {
        let kind = if self.to_create {
            TxKind::Create
        } else {
            TxKind::Call(Address::from(self.to_address))
        };

        // Map selector to valid tx types: 0 (legacy), 1 (EIP-2930), 2 (EIP-1559), 0x4A (seismic)
        let tx_type = match self.tx_type_selector % 4 {
            0 => 0u8,
            1 => 1,
            2 => 2,
            _ => 0x4A,
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
                chain_id: Some(5123),
                nonce: self.nonce,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type,
            },
            tx_hash: Default::default(),
            rng_mode: if self.rng_mode_execution {
                RngMode::Execution
            } else {
                RngMode::Simulation
            },
        }
    }

    /// Convert to a non-seismic `SeismicTransaction<TxEnv>` (for differential testing).
    pub fn into_eth_compatible_tx(mut self) -> SeismicTransaction<TxEnv> {
        // Force non-seismic tx type
        self.tx_type_selector = self.tx_type_selector % 3;
        self.into_seismic_tx()
    }
}
