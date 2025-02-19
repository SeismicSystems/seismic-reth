//! clap [Args](clap::Args) for RPC related arguments.

use std::net::IpAddr;

use clap::Args;
use reth_enclave::{ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT};

/// Parameters for configuring the enclave more granularity via CLI
#[derive(Debug, Clone, Args, PartialEq, Eq, Copy)]
#[command(next_help_heading = "Enclave")]
pub struct EnclaveArgs {
    /// Auth server address to listen on
    #[arg(long = "enclave.endpoint-addr", default_value_t = ENCLAVE_DEFAULT_ENDPOINT_ADDR)]
    pub enclave_server_addr: IpAddr,

    /// Auth server port to listen on
    #[arg(long = "enclave.endpoint-port", default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    pub enclave_server_port: u16,

    /// Spin up mock server for testing purpose
    #[arg(long = "enclave.mock-server", action = clap::ArgAction::SetTrue)]
    pub mock_server: bool,
}

impl Default for EnclaveArgs {
    fn default() -> Self {
        Self {
            enclave_server_addr: ENCLAVE_DEFAULT_ENDPOINT_ADDR,
            enclave_server_port: ENCLAVE_DEFAULT_ENDPOINT_PORT,
            mock_server: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::enclave::EnclaveArgs;
    use clap::{Args, Parser};

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_tee_args_parser() {
        let args = CommandParser::<EnclaveArgs>::parse_from(["reth node"]).args;

        let addr = args.enclave_server_addr;
        let port = args.enclave_server_port;
        let mock = args.mock_server;

        assert_eq!(port, ENCLAVE_DEFAULT_ENDPOINT_PORT);
        assert_eq!(addr, ENCLAVE_DEFAULT_ENDPOINT_ADDR);
        assert_eq!(mock, false);
    }
}
