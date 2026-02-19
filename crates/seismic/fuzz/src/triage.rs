//! Crash triage and dependency tagging for fuzz targets.
//!
//! Each fuzz target is tagged with the seismic dependency subset it exercises,
//! enabling attribution of crashes to specific dependencies.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeismicDep {
    SeismicAlloyConsensus,
    SeismicAlloyCore,
    SeismicRevm,
    AlloySeismicEvm,
    SeismicEnclave,
    SeismicTrie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrashCategory {
    EncodingDecoding,
    EvmExecution,
    Precompile,
    FlaggedStorage,
    TxValidation,
    Differential,
}

pub struct FuzzTargetMeta {
    pub name: &'static str,
    pub deps: &'static [SeismicDep],
    pub crash_category: CrashCategory,
}

pub const FUZZ_TARGETS: &[FuzzTargetMeta] = &[
    // Encoding/decoding
    FuzzTargetMeta {
        name: "tx_decode_arbitrary_bytes",
        deps: &[SeismicDep::SeismicAlloyConsensus, SeismicDep::SeismicAlloyCore],
        crash_category: CrashCategory::EncodingDecoding,
    },
    FuzzTargetMeta {
        name: "tx_roundtrip_2718",
        deps: &[SeismicDep::SeismicAlloyConsensus, SeismicDep::SeismicAlloyCore],
        crash_category: CrashCategory::EncodingDecoding,
    },
    FuzzTargetMeta {
        name: "tx_roundtrip_compact",
        deps: &[SeismicDep::SeismicAlloyConsensus, SeismicDep::SeismicAlloyCore],
        crash_category: CrashCategory::EncodingDecoding,
    },
    FuzzTargetMeta {
        name: "receipt_decode_arbitrary",
        deps: &[SeismicDep::SeismicAlloyConsensus, SeismicDep::SeismicAlloyCore],
        crash_category: CrashCategory::EncodingDecoding,
    },
    // Precompiles
    FuzzTargetMeta {
        name: "precompile_ecdh",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::Precompile,
    },
    FuzzTargetMeta {
        name: "precompile_aes_encrypt",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::Precompile,
    },
    FuzzTargetMeta {
        name: "precompile_aes_decrypt",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::Precompile,
    },
    FuzzTargetMeta {
        name: "precompile_hkdf",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::Precompile,
    },
    FuzzTargetMeta {
        name: "precompile_secp256k1_sign",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::Precompile,
    },
    FuzzTargetMeta {
        name: "precompile_rng",
        deps: &[SeismicDep::SeismicRevm],
        crash_category: CrashCategory::Precompile,
    },
    // Flagged storage
    FuzzTargetMeta {
        name: "storage_access_control",
        deps: &[SeismicDep::SeismicRevm],
        crash_category: CrashCategory::FlaggedStorage,
    },
    // EVM execution
    FuzzTargetMeta {
        name: "evm_transact",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::AlloySeismicEvm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::EvmExecution,
    },
    FuzzTargetMeta {
        name: "evm_transact_seismic_tx",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::AlloySeismicEvm, SeismicDep::SeismicEnclave],
        crash_category: CrashCategory::EvmExecution,
    },
    // Differential
    FuzzTargetMeta {
        name: "differential_eth_vs_seismic",
        deps: &[SeismicDep::SeismicRevm, SeismicDep::AlloySeismicEvm],
        crash_category: CrashCategory::Differential,
    },
    // Tx validation
    FuzzTargetMeta {
        name: "validate_seismic_tx",
        deps: &[SeismicDep::SeismicAlloyConsensus],
        crash_category: CrashCategory::TxValidation,
    },
];
