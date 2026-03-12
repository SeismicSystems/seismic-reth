//! clap [Args](clap::Args) for address screening configuration.

use clap::Args;

/// Parameters for configuring the ECSD address screening sidecar.
///
/// When enabled, transactions are screened against a blocklist via the ECSD
/// (Ethereum Compliance Screening Daemon) gRPC service before pool admission.
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "Address Screening")]
pub struct ScreeningArgs {
    /// Enable address screening via ECSD sidecar.
    #[arg(long = "screening.enable", default_value_t = false)]
    pub enable: bool,

    /// gRPC endpoint of the ECSD sidecar.
    #[arg(long = "screening.endpoint", default_value = "http://127.0.0.1:9090")]
    pub endpoint: String,

    /// Request timeout in milliseconds.
    #[arg(long = "screening.timeout-ms", default_value_t = 100)]
    pub timeout_ms: u64,

    /// Behavior when ECSD is unavailable: "open" or "closed".
    ///
    /// - "open": transactions pass through when ECSD is unreachable (permissive)
    /// - "closed": transactions are rejected when ECSD is unreachable (restrictive)
    #[arg(
        long = "screening.fail-mode",
        default_value = "open",
        value_parser = clap::builder::PossibleValuesParser::new(["open", "closed"])
    )]
    pub fail_mode: String,
}

impl Default for ScreeningArgs {
    fn default() -> Self {
        Self {
            enable: false,
            endpoint: "http://127.0.0.1:9090".to_string(),
            timeout_ms: 100,
            fail_mode: "open".to_string(),
        }
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
    fn test_default_screening_args() {
        let args = CommandParser::<ScreeningArgs>::parse_from(["reth node"]).args;

        assert!(!args.enable);
        assert_eq!(args.endpoint, "http://127.0.0.1:9090");
        assert_eq!(args.timeout_ms, 100);
        assert_eq!(args.fail_mode, "open");
    }

    #[test]
    fn test_screening_args_all_flags() {
        let args = CommandParser::<ScreeningArgs>::parse_from([
            "reth node",
            "--screening.enable",
            "--screening.endpoint",
            "http://10.0.0.5:9090",
            "--screening.timeout-ms",
            "200",
            "--screening.fail-mode",
            "closed",
        ])
        .args;

        assert!(args.enable);
        assert_eq!(args.endpoint, "http://10.0.0.5:9090");
        assert_eq!(args.timeout_ms, 200);
        assert_eq!(args.fail_mode, "closed");
    }

    #[test]
    #[should_panic(expected = "invalid value 'close'")]
    fn test_screening_args_invalid_fail_mode() {
        // Typo: "close" instead of "closed" should fail fast
        let _args = CommandParser::<ScreeningArgs>::try_parse_from([
            "reth node",
            "--screening.fail-mode",
            "close",
        ])
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid value 'permissive'")]
    fn test_screening_args_invalid_fail_mode_permissive() {
        // Invalid value should fail fast
        let _args = CommandParser::<ScreeningArgs>::try_parse_from([
            "reth node",
            "--screening.fail-mode",
            "permissive",
        ])
        .unwrap();
    }
}
