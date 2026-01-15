//! clap [Args](clap::Args) for RPC related arguments.
use std::net::{IpAddr, Ipv4Addr};
use clap::Args;

const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
const ENCLAVE_DEFAULT_ENDPOINT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Parameters for configuring the enclave more granularity via CLI
#[derive(Debug, Clone, Args, PartialEq, Eq, Copy)]
#[command(next_help_heading = "Enclave")]
pub struct EnclaveArgs {
    /// Auth server address to listen on
    #[arg(long = "enclave.endpoint-addr", default_value_t = ENCLAVE_DEFAULT_ENDPOINT_IP.try_into().unwrap())]
    pub enclave_server_addr: IpAddr,

    /// Auth server port to listen on
    #[arg(long = "enclave.endpoint-port", default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    pub enclave_server_port: u16,

    /// How many failures to tolerate before we panic
    #[arg(long = "enclave.retries", default_value_t = 0)]
    pub retries: u32,

    /// How many seconds to pause between retries
    #[arg(long = "enclave.retry-seconds", default_value_t = 30)]
    pub retry_seconds: u16,

    /// Spin up mock server for testing purpose
    #[arg(long = "enclave.mock-server", action = clap::ArgAction::SetTrue)]
    pub mock_server: bool,

    /// Enclave client timeout
    #[arg(long = "enclave.timeout", default_value_t = 5)]
    pub enclave_timeout: u64,
}

impl Default for EnclaveArgs {
    fn default() -> Self {
        Self {
            enclave_server_addr: ENCLAVE_DEFAULT_ENDPOINT_IP,
            enclave_server_port: ENCLAVE_DEFAULT_ENDPOINT_PORT,
            mock_server: false,
            enclave_timeout: 5,
            retries: 5,
            retry_seconds: 30,
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
    fn test_enclave_args_parser() {
        let args = CommandParser::<EnclaveArgs>::parse_from(["reth node"]).args;

        let addr = args.enclave_server_addr;
        let port = args.enclave_server_port;
        let mock = args.mock_server;

        assert_eq!(port, 7878);
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(!mock);
    }
}
