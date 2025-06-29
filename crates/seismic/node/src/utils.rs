//! test utils for the e2e tests

/// Test utils for the seismic rpc api
pub mod test_utils {
    use alloy_primitives::Address;
    use alloy_rpc_types::{Block, Header, Transaction, TransactionReceipt};
    use jsonrpsee::http_client::HttpClient;
    use reth_rpc_eth_api::EthApiClient;
    use reth_seismic_chainspec::SEISMIC_DEV;
    use serde_json::Value;
    use std::{path::PathBuf, process::Stdio};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
        sync::mpsc,
    };

    pub use reth_seismic_primitives::test_utils::{
        client_decrypt, client_encrypt, get_ciphertext, get_client_io_sk, get_encryption_nonce,
        get_network_public_key, get_plaintext, get_seismic_elements, get_seismic_tx,
        get_signed_seismic_tx, get_signed_seismic_tx_bytes, get_signed_seismic_tx_encoding,
        get_signed_seismic_tx_typed_data, get_signing_private_key, get_unsigned_seismic_tx_request,
        get_unsigned_seismic_tx_typed_data, get_wrong_private_key, sign_seismic_tx, sign_tx,
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
                .arg(SeismicRethTestCommand::data_dir().to_str().unwrap())
                .arg("--dev")
                .arg("--dev.block-max-transactions")
                .arg("1")
                .arg("--enclave.mock-server")
                .arg("-vvvv")
                .current_dir(workspace_root)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
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
                std::panic::set_hook(Box::new(|info| {
                    eprintln!("❌ PANIC DETECTED: {:?}", info);
                }));

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
                println!("✅ Exiting loop.");

                child.kill().await.unwrap();
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
            format!("http://127.0.0.1:8545")
        }
    }

    /// Get the nonce from the client
    pub async fn get_nonce(client: &HttpClient, address: Address) -> u64 {
        let nonce =
            EthApiClient::<Transaction, Block, TransactionReceipt, Header>::transaction_count(
                client, address, None,
            )
            .await
            .unwrap();
        nonce.wrapping_to::<u64>()
    }
}
