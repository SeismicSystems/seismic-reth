//! clap [Args](clap::Args) for RPC related arguments.

use std::net::{IpAddr, Ipv4Addr};

use clap::Args;

/// Parameters for configuring the enclave more granularity via CLI
#[derive(Debug, Clone, Args, PartialEq, Eq, Copy)]
#[command(next_help_heading = "Enclave")]
pub struct EnclaveArgs {
    /// Auth server address to listen on
    #[arg(long = "enclave.endpoint-addr", default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    pub enclave_server_addr: IpAddr,

    /// Auth server port to listen on
    #[arg(long = "enclave.endpoint-port", default_value_t = 7878)]
    pub enclave_server_port: u16,

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
            enclave_server_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            enclave_server_port: 7878,
            mock_server: false,
            enclave_timeout: 5,
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
