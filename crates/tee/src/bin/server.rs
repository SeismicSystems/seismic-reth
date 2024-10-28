use std::net::SocketAddr;

use anyhow::{Ok, Result};
use reth_tee::server::build_server;

#[tokio::main]
async fn main() -> Result<()> {
    let server = build_server();

    let _ = server.await;

    Ok(())
}
