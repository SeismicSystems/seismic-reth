//! clap [Args](clap::Args) for RPC related arguments.

use std::net::IpAddr;

use clap::Args;
use reth_tee::{TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT};

/// Parameters for configuring the tee more granularity via CLI
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "TEE")]
pub struct TeeArgs {
    /// Auth server address to listen on
    #[arg(long = "tee.endpoint-addr", default_value_t = TEE_DEFAULT_ENDPOINT_ADDR)]
    pub tee_server_addr: IpAddr,

    /// Auth server port to listen on
    #[arg(long = "tee.endpoint-port", default_value_t = TEE_DEFAULT_ENDPOINT_PORT)]
    pub tee_server_port: u16,

    /// Spin up mock server for testing purpose
    #[arg(long = "tee.mock-server", action = clap::ArgAction::SetTrue)]
    pub mock_server: bool,
}

impl Default for TeeArgs {
    fn default() -> Self {
        Self {
            tee_server_addr: TEE_DEFAULT_ENDPOINT_ADDR,
            tee_server_port: TEE_DEFAULT_ENDPOINT_PORT,
            mock_server: false,
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
    fn test_tee_args_parser() {
        let args = CommandParser::<TeeArgs>::parse_from(["reth node"]).args;

        let addr = args.tee_server_addr;
        let port = args.tee_server_port;
        let mock = args.mock_server;

        assert_eq!(port, TEE_DEFAULT_ENDPOINT_PORT);
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(mock, false);
    }
}
