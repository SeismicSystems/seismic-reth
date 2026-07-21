//! clap [Args](clap::Args) for configuring the node's purpose-key source.
use clap::{Args, ValueEnum};
use std::{
    fmt::{self, Display},
    path::PathBuf,
};

// Mirrors `seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH` (this crate cannot
// depend on it); lockstep is asserted by a test in `reth-seismic-node`.
const DEFAULT_CUSTODIAN_SOCKET_PATH: &str = "/run/seismic/custodian/custodian.sock";

/// Where the node sources its purpose keys (the tx-io keypair and RNG ikm).
///
/// An enum rather than a bool so future sources (e.g. a key file) can be added
/// without introducing a second selector flag.
#[derive(Debug, Copy, Clone, ValueEnum, PartialEq, Eq)]
pub enum PurposeKeysSource {
    /// Fetch the keys from the key custodian's Unix socket (TEE deployments).
    Custodian,
    /// Use the well-known keys built into the binary (publicly known, no
    /// confidentiality); for dev nodes and pre-TEE deployments that run no TEE at all.
    // TODO: the built-in keys are currently the live testnet's network keys, and the
    // only key material reth can run without a custodian — supplying anything else
    // (per-network pre-TEE keys, arbitrary keys for testing) needs a future source,
    // e.g. `file`.
    BuiltIn,
}

impl Display for PurposeKeysSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custodian => write!(f, "custodian"),
            Self::BuiltIn => write!(f, "built-in"),
        }
    }
}

/// CLI parameters selecting the node's purpose-key source: the key custodian's
/// Unix socket (TEE deployments) or the built-in well-known keys
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "Purpose Keys")]
pub struct PurposeKeysArgs {
    /// Where the node sources its purpose keys. `custodian` fetches them from the key
    /// custodian's Unix socket (TEE deployments); `built-in` uses the well-known keys
    /// built into the binary (publicly known, no confidentiality). With `built-in` the
    /// `--seismic.custodian.*` flags are unused.
    #[arg(long = "seismic.purpose-keys-source", default_value_t = PurposeKeysSource::Custodian)]
    pub source: PurposeKeysSource,

    /// Transport knobs for the custodian socket; only used when `source` is `custodian`.
    #[command(flatten)]
    pub custodian: CustodianArgs,
}

/// CLI parameters for fetching purpose keys from the key custodian's Unix socket.
///
/// All of these are only used with `--seismic.purpose-keys-source custodian`; they are
/// ignored under `--seismic.purpose-keys-source built-in` (keys built into the binary).
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "Purpose Keys")]
pub struct CustodianArgs {
    /// Path of the key custodian's Unix socket, the source of the node's purpose
    /// keys on TEE deployments. Only used with `--seismic.purpose-keys-source custodian`.
    #[arg(long = "seismic.custodian.socket", default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    pub socket: PathBuf,

    /// How many boot-time fetch failures to tolerate before we panic.
    /// Total attempts = `retries` + 1 (one initial attempt plus `retries` re-attempts).
    /// Only used with `--seismic.purpose-keys-source custodian`.
    #[arg(long = "seismic.custodian.retries", default_value_t = 5)]
    pub retries: u32,

    /// Timeout in seconds for each purpose-key fetch attempt against the custodian socket.
    /// Only used with `--seismic.purpose-keys-source custodian`.
    #[arg(long = "seismic.custodian.timeout-seconds", default_value_t = 5)]
    pub timeout_seconds: u64,

    /// How many seconds to wait before retrying after a failed attempt.
    /// Only used with `--seismic.purpose-keys-source custodian`.
    #[arg(long = "seismic.custodian.retry-seconds", default_value_t = 30)]
    pub retry_seconds: u16,
}

impl Default for PurposeKeysArgs {
    fn default() -> Self {
        Self { source: PurposeKeysSource::Custodian, custodian: CustodianArgs::default() }
    }
}

impl Default for CustodianArgs {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(DEFAULT_CUSTODIAN_SOCKET_PATH),
            retries: 5,
            timeout_seconds: 5,
            retry_seconds: 30,
        }
    }
}

impl AsRef<PurposeKeysArgs> for PurposeKeysArgs {
    fn as_ref(&self) -> &PurposeKeysArgs {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, Parser};

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_purpose_keys_args_parser() {
        let args = CommandParser::<PurposeKeysArgs>::parse_from(["reth node"]).args;

        assert_eq!(args, PurposeKeysArgs::default());
        assert_eq!(args.source, PurposeKeysSource::Custodian);
        assert_eq!(args.custodian.socket, std::path::Path::new(DEFAULT_CUSTODIAN_SOCKET_PATH));
        assert_eq!(args.custodian.retries, 5);
        assert_eq!(args.custodian.timeout_seconds, 5);
        assert_eq!(args.custodian.retry_seconds, 30);
    }

    #[test]
    fn test_purpose_keys_source_selects_built_in() {
        let args = CommandParser::<PurposeKeysArgs>::parse_from([
            "reth node",
            "--seismic.purpose-keys-source",
            "built-in",
        ])
        .args;

        assert_eq!(args.source, PurposeKeysSource::BuiltIn);
    }

    #[test]
    fn test_custodian_args_parse_under_purpose_keys() {
        let args = CommandParser::<PurposeKeysArgs>::parse_from([
            "reth node",
            "--seismic.custodian.socket",
            "/tmp/custodian.sock",
            "--seismic.custodian.retries",
            "9",
            "--seismic.custodian.timeout-seconds",
            "7",
            "--seismic.custodian.retry-seconds",
            "11",
        ])
        .args;

        assert_eq!(args.custodian.socket, std::path::Path::new("/tmp/custodian.sock"));
        assert_eq!(args.custodian.retries, 9);
        assert_eq!(args.custodian.timeout_seconds, 7);
        assert_eq!(args.custodian.retry_seconds, 11);
    }
}
