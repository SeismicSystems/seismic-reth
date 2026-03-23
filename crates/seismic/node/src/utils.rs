//! test utils for the e2e tests

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test utilities - panics are acceptable

#[cfg(feature = "test-utils")]
use crate::node::SeismicNode;
#[cfg(feature = "test-utils")]
use crate::purpose_keys::init_purpose_keys;
#[cfg(feature = "test-utils")]
use alloy_primitives::{Address, B256};
#[cfg(feature = "test-utils")]
use alloy_rpc_types_engine::PayloadAttributes;
#[cfg(feature = "test-utils")]
use reth_e2e_test_utils::{transaction::TransactionTestContext, wallet::Wallet, NodeHelperType};
#[cfg(feature = "test-utils")]
use reth_node_api::NodeTypesWithDBAdapter;
#[cfg(feature = "test-utils")]
use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes};
#[cfg(feature = "test-utils")]
use reth_provider::providers::BlockchainProvider;
#[cfg(feature = "test-utils")]
use reth_seismic_chainspec::SEISMIC_DEV;
#[cfg(feature = "test-utils")]
use reth_seismic_primitives::SeismicPrimitives;
#[cfg(feature = "test-utils")]
use reth_tasks::TaskManager;
#[cfg(feature = "test-utils")]
use seismic_enclave::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk, GetPurposeKeysResponse,
};
#[cfg(feature = "test-utils")]
use std::sync::{Arc, Once};
#[cfg(feature = "test-utils")]
use tokio::sync::Mutex;

#[cfg(feature = "test-utils")]
use reth_e2e_test_utils::TmpDB;

/// Seismic returns times in milliseconds
#[cfg(feature = "test-utils")]
pub const SEISMIC_TIMESTAMP_MULTIPLIER: u64 = 1000;

#[cfg(feature = "test-utils")]
static INIT_KEYS: Once = Once::new();

/// Initializes mock purpose keys for tests. Safe to call multiple times.
#[cfg(feature = "test-utils")]
pub fn ensure_mock_purpose_keys() {
    INIT_KEYS.call_once(|| {
        init_purpose_keys(GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        });
    });
}

/// Seismic Node Helper type
#[cfg(feature = "test-utils")]
pub type SeismicTestNode =
    NodeHelperType<SeismicNode, BlockchainProvider<NodeTypesWithDBAdapter<SeismicNode, TmpDB>>>;

/// Creates the initial setup with `num_nodes` of the seismic node config, started and connected.
#[cfg(feature = "test-utils")]
pub async fn setup(num_nodes: usize) -> eyre::Result<(Vec<SeismicTestNode>, TaskManager, Wallet)> {
    reth_e2e_test_utils::setup_engine(
        num_nodes,
        SEISMIC_DEV.clone(),
        false,
        Default::default(),
        seismic_payload_attributes,
    )
    .await
}

/// Advance the chain with sequential payloads returning them in the end.
#[cfg(feature = "test-utils")]
pub async fn advance_chain(
    length: usize,
    node: &mut SeismicTestNode,
    wallet: Arc<Mutex<Wallet>>,
) -> eyre::Result<Vec<EthBuiltPayload<SeismicPrimitives>>> {
    node.advance(length as u64, |_| {
        let wallet = wallet.clone();
        Box::pin(async move {
            let mut wallet = wallet.lock().await;
            let nonce = wallet.inner_nonce;
            wallet.inner_nonce += 1;
            let tx = alloy_rpc_types_eth::TransactionRequest {
                nonce: Some(nonce),
                value: Some(alloy_primitives::U256::from(100)),
                to: Some(alloy_primitives::TxKind::Call(Address::random())),
                gas: Some(21000),
                max_fee_per_gas: Some(20e9 as u128),
                max_priority_fee_per_gas: Some(20e9 as u128),
                chain_id: Some(wallet.chain_id),
                ..Default::default()
            };
            let signed = TransactionTestContext::sign_tx(wallet.inner.clone(), tx).await;
            alloy_eips::eip2718::Encodable2718::encoded_2718(&signed).into()
        })
    })
    .await
}

/// Helper function to create a new eth payload attributes for seismic
#[cfg(feature = "test-utils")]
pub fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp: timestamp * SEISMIC_TIMESTAMP_MULTIPLIER,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Test utils for the seismic rpc api
pub mod test_utils {
    use alloy_primitives::Address;
    use alloy_rpc_types::{Block, Header, Transaction, TransactionReceipt};
    use jsonrpsee::http_client::HttpClient;
    use reth_rpc_eth_api::EthApiClient;
    use reth_seismic_chainspec::SEISMIC_DEV;
    use seismic_alloy_rpc_types::SeismicTransactionRequest;
    use serde_json::Value;
    use std::{path::PathBuf, process::Stdio};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
        sync::mpsc,
    };

    pub use reth_seismic_primitives::test_utils::{
        client_decrypt, client_encrypt, get_ciphertext, get_client_io_sk, get_encryption_nonce,
        get_network_public_key, get_plaintext, get_seismic_elements, get_seismic_metadata,
        get_seismic_tx, get_signed_seismic_tx, get_signed_seismic_tx_bytes,
        get_signed_seismic_tx_encoding, get_signed_seismic_tx_typed_data, get_signing_private_key,
        get_unsigned_seismic_tx_request, get_unsigned_seismic_tx_typed_data, get_wrong_private_key,
        sign_seismic_tx, sign_tx,
    };

    // use reth_seismic_evm::engine::SeismicEngineValidator;
    /// Seismic reth test command
    #[derive(Debug)]
    pub struct SeismicRethTestCommand();
    impl SeismicRethTestCommand {
        /// Run the seismic reth test command
        pub async fn run(tx: mpsc::Sender<()>, mut shutdown_rx: mpsc::Receiver<()>) {
            let output = Command::new("cargo")
                .arg("metadata")
                .arg("--format-version=1")
                .output()
                .await
                .unwrap();
            let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
            let workspace_root = metadata.get("workspace_root").unwrap().as_str().unwrap();
            println!("Workspace root: {}", workspace_root);

            let mut child = Command::new("cargo")
                .arg("run")
                .arg("--bin")
                .arg("seismic-reth") // Specify the binary name
                .arg("--")
                .arg("node")
                .arg("--datadir")
                .arg(Self::data_dir().to_str().unwrap())
                .arg("--dev")
                .arg("--dev.block-max-transactions")
                .arg("1")
                .arg("--enclave.mock-server")
                .arg("-vvvv")
                .arg("--disable-discovery")
                // Use OS-assigned random ports for p2p (default 30303) and auth RPC (default 8551)
                // to avoid "address already in use" errors on nextest retries. The test only talks
                // to the HTTP RPC port (8545), so these ports don't matter.
                .arg("--port")
                .arg("0")
                .arg("--authrpc.port")
                .arg("0")
                .current_dir(workspace_root)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                // Ensure the child process is killed when dropped (e.g. on test panic/timeout).
                // Without this, a test failure leaves an orphaned reth process holding ports.
                .kill_on_drop(true)
                .spawn()
                .expect("Failed to start the binary");

            tokio::spawn(async move {
                let stdout = child.stdout.as_mut().expect("Failed to capture stdout");
                let stderr = child.stderr.as_mut().expect("Failed to capture stderr");
                let mut stdout_reader = BufReader::new(stdout);
                let mut stderr_reader = BufReader::new(stderr);
                let mut stdout_line = String::new();
                let mut stderr_line = String::new();
                let mut sent = false;

                loop {
                    tokio::select! {
                        result = stdout_reader.read_line(&mut stdout_line) => {
                            if result.unwrap() == 0 {
                                eprintln!("🛑 STDOUT reached EOF! Breaking loop.");
                                break;
                            }
                            eprint!("{}", stdout_line);

                            if stdout_line.contains("Starting consensus engine") && !sent {
                                eprintln!("🚀 Reth server is ready!");
                                let _ = tx.send(()).await;
                                sent = true;
                            }
                            stdout_line.clear();
                            tokio::io::stdout().flush().await.unwrap();
                        }

                        result = stderr_reader.read_line(&mut stderr_line) => {
                            if result.unwrap() == 0 {
                                eprintln!("🛑 STDERR reached EOF! Breaking loop.");
                                break;
                            }
                            eprint!("{}", stderr_line);
                            stderr_line.clear();
                        }

                        Some(_) = shutdown_rx.recv() => {
                            eprintln!("🛑 Shutdown signal received! Breaking loop.");
                            break;
                        }
                    }
                }
                // kill_on_drop handles cleanup, but we explicitly kill here for a clean
                // shutdown on the happy path (avoids waiting for drop).
                let _ = child.kill().await;
                println!("✅ Killed child process.");
            });
        }

        /// Get the data directory for the seismic reth test command
        pub fn data_dir() -> PathBuf {
            static TEMP_DIR: once_cell::sync::Lazy<tempfile::TempDir> =
                once_cell::sync::Lazy::new(|| tempfile::tempdir().unwrap());
            TEMP_DIR.path().to_path_buf()
        }

        /// Get the chain id for the seismic reth test command
        pub fn chain_id() -> u64 {
            SEISMIC_DEV.chain().into()
        }

        /// Get the url for the seismic reth test command
        pub fn url() -> String {
            "http://127.0.0.1:8545".to_string()
        }
    }

    /// Get the nonce from the client
    pub async fn get_nonce(client: &HttpClient, address: Address) -> u64 {
        let nonce = EthApiClient::<
            SeismicTransactionRequest,
            Transaction,
            Block,
            TransactionReceipt,
            Header,
        >::transaction_count(client, address, None)
        .await
        .unwrap();
        nonce.wrapping_to::<u64>()
    }
}
