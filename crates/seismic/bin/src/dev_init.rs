#![allow(missing_docs)]

use seismic_node::utils::seismic_reth_dev_init;

#[tokio::main]
async fn main() {
    // Initialize your application
    seismic_reth_dev_init().await;

    // Keep the binary running by waiting indefinitely
    println!("Press Ctrl+C to exit...");
    tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    println!("Shutting down...");
}
