//! clap [Args](clap::Args) for configuring the node's purpose-key source.
use clap::Args;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
const ENCLAVE_DEFAULT_ENDPOINT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
// Mirrors `seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH` (this crate cannot
// depend on it); lockstep is asserted by a test in `reth-seismic-node`.
const ENCLAVE_DEFAULT_CUSTODIAN_SOCKET: &str = "/run/seismic/custodian/custodian.sock";

/// CLI parameters selecting the node's purpose-key source: the key custodian's
/// Unix socket (TEE deployments) or the built-in well-known keys
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "Enclave")]
pub struct EnclaveArgs {
    /// Use the built-in well-known keys (publicly known, no confidentiality) as the
    /// node's purpose keys instead of fetching them from the custodian. When true,
    /// the other flags below are not used.
    #[arg(long = "enclave.mock-server", action = clap::ArgAction::SetTrue)]
    pub mock_server: bool,

    /// Path of the key custodian's Unix socket, the source of the node's purpose
    /// keys on TEE deployments
    #[arg(long = "enclave.custodian-socket", default_value = ENCLAVE_DEFAULT_CUSTODIAN_SOCKET)]
    pub custodian_socket: PathBuf,

    /// How many boot-time fetch failures to tolerate before we panic.
    /// Total attempts = `retries` + 1 (one initial attempt plus `retries` re-attempts).
    #[arg(long = "enclave.retries", default_value_t = 5)]
    pub retries: u32,

    /// Timeout in seconds for each purpose-key fetch attempt against the custodian socket
    #[arg(long = "enclave.timeout", default_value_t = 5)]
    pub enclave_timeout: u64,

    /// How many seconds to wait before retrying after a failed attempt
    #[arg(long = "enclave.retry-seconds", default_value_t = 30)]
    pub retry_seconds: u16,

    /// DEPRECATED: has no effect; kept so existing command lines keep parsing.
    /// Purpose keys are now fetched from the custodian socket.
    #[arg(long = "enclave.endpoint-addr", default_value_t = ENCLAVE_DEFAULT_ENDPOINT_IP.try_into().unwrap())]
    pub enclave_server_addr: IpAddr,

    /// DEPRECATED: has no effect; kept so existing command lines keep parsing.
    /// Purpose keys are now fetched from the custodian socket.
    #[arg(long = "enclave.endpoint-port", default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    pub enclave_server_port: u16,
}

impl Default for EnclaveArgs {
    fn default() -> Self {
        Self {
            mock_server: false,
            custodian_socket: PathBuf::from(ENCLAVE_DEFAULT_CUSTODIAN_SOCKET),
            retries: 5,
            enclave_timeout: 5,
            retry_seconds: 30,
            enclave_server_addr: ENCLAVE_DEFAULT_ENDPOINT_IP,
            enclave_server_port: ENCLAVE_DEFAULT_ENDPOINT_PORT,
        }
    }
}

impl AsRef<EnclaveArgs> for EnclaveArgs {
    fn as_ref(&self) -> &EnclaveArgs {
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
    fn test_enclave_args_parser() {
        let args = CommandParser::<EnclaveArgs>::parse_from(["reth node"]).args;

        assert_eq!(args.enclave_server_port, ENCLAVE_DEFAULT_ENDPOINT_PORT);
        assert_eq!(args.enclave_server_addr, ENCLAVE_DEFAULT_ENDPOINT_IP);
        assert_eq!(args.custodian_socket, std::path::Path::new(ENCLAVE_DEFAULT_CUSTODIAN_SOCKET));
        assert_eq!(args.mock_server, false);
    }
}
