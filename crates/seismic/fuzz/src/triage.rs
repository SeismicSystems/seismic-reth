//! Crash triage and dependency tagging for fuzz targets.
//!
//! Each fuzz target is tagged with the seismic dependency subset it exercises,
//! enabling attribution of crashes to specific dependencies.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Seismic dependency identifiers.
pub enum SeismicDep {
    /// `seismic-alloy-consensus`
    SeismicAlloyConsensus,
    /// `seismic-alloy-core`
    SeismicAlloyCore,
    /// `seismic-revm`
    SeismicRevm,
    /// `seismic-evm`
    AlloySeismicEvm,
    /// `enclave`
    SeismicEnclave,
    /// `seismic-trie`
    SeismicTrie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Crash category for classification
pub enum CrashCategory {
    /// Encoding/decoding
    EncodingDecoding,
    /// EVM execution
    EvmExecution,
    /// Precompiles
    Precompile,
    /// Flagged storage
    FlaggedStorage,
    /// Tx validation
    TxValidation,
    /// Differential
    Differential,
}

/// Metadata for a fuzz target.
#[derive(Debug)]
pub struct FuzzTargetMeta {
    /// The name of the fuzz target.
    pub name: &'static str,
    /// The dependencies exercised by the fuzz target.
    pub deps: &'static [SeismicDep],
    /// The crash category of the fuzz target.
    pub crash_category: CrashCategory,
}

/// Registry of all fuzz targets and their dependency metadata.
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
