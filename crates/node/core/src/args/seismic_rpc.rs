//! clap [Args](clap::Args) for Seismic-specific RPC configuration, plus a process-wide handle so
//! the RPC layer can read them.

use clap::Args;
use reth_transaction_pool::validate::DEFAULT_MAX_TX_INPUT_BYTES;
use std::sync::OnceLock;

/// Seismic-specific RPC limits.
///
/// A signed read (`eth_call`/`eth_estimateGas`/`eth_callMany`/`eth_simulateV1` carrying a signed
/// seismic payload) decrypts its calldata at the RPC layer before execution — RLP decode, keccak
/// signature hash, secp256k1 recovery, ECDH, AES-GCM — none of it metered by EVM gas. Unlike a
/// real transaction it never enters the mempool, so the [`DEFAULT_MAX_TX_INPUT_BYTES`] per-tx size
/// limit does not apply. This caps a signed read at that same size by default, rejected before any
/// of that crypto runs and independently of `rpc.max-request-size`.
#[derive(Debug, Clone, Copy, Args, PartialEq, Eq)]
#[command(next_help_heading = "Seismic RPC")]
pub struct SeismicRpcArgs {
    /// Maximum accepted signed-read payload size, in bytes.
    #[arg(
        long = "seismic.rpc.max-signed-read-input-bytes",
        default_value_t = DEFAULT_MAX_TX_INPUT_BYTES
    )]
    pub max_signed_read_input_bytes: usize,
}

impl Default for SeismicRpcArgs {
    fn default() -> Self {
        Self { max_signed_read_input_bytes: DEFAULT_MAX_TX_INPUT_BYTES }
    }
}

/// Process-wide Seismic RPC limits.
///
/// The signed-read guard lives in a free function in `reth-seismic-rpc`
/// (`recover_raw_seismic_call_tx`) that has no channel to the parsed CLI args. The CLI sets this
/// once at startup, before the node is built, and the guard reads it back. A second set is ignored
/// (first wins) so in-process test harnesses that build several nodes don't panic.
static SEISMIC_RPC_ARGS: OnceLock<SeismicRpcArgs> = OnceLock::new();

/// Store the Seismic RPC limits for the RPC layer to read. Should be called once at startup.
pub fn init_seismic_rpc_args(args: SeismicRpcArgs) {
    let _ = SEISMIC_RPC_ARGS.set(args);
}

/// Read the Seismic RPC limits, falling back to defaults if never initialized (e.g. tests or
/// embedders that build the node directly without going through the CLI).
pub fn seismic_rpc_args() -> SeismicRpcArgs {
    SEISMIC_RPC_ARGS.get().copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, Parser};

    /// A helper type to parse Args more easily.
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_seismic_rpc_args_default() {
        let args = CommandParser::<SeismicRpcArgs>::parse_from(["reth node"]).args;
        assert_eq!(args.max_signed_read_input_bytes, DEFAULT_MAX_TX_INPUT_BYTES);
    }

    #[test]
    fn test_seismic_rpc_args_override() {
        let args = CommandParser::<SeismicRpcArgs>::parse_from([
            "reth node",
            "--seismic.rpc.max-signed-read-input-bytes",
            "4096",
        ])
        .args;
        assert_eq!(args.max_signed_read_input_bytes, 4096);
    }
}
