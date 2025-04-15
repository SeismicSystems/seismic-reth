use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, TxKind, B256};
use alloy_rpc_types::engine::PayloadAttributes;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use reth_chainspec::SEISMIC_DEV;
use reth_node_ethereum::EthEvmConfig;
use reth_payload_builder::EthPayloadBuilderAttributes;
use secp256k1::{PublicKey, SecretKey};
use serde_json::Value;
use std::{path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc,
};

/// Seismic reth test command
#[derive(Debug)]
pub struct SeismicRethTestCommand();
impl SeismicRethTestCommand {
    /// Run the seismic reth test command
    pub async fn run(tx: mpsc::Sender<()>, mut shutdown_rx: mpsc::Receiver<()>) {
        let output =
            Command::new("cargo").arg("metadata").arg("--format-version=1").output().await.unwrap();
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

/// Helper function to create a new eth payload attributes
pub fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Test utils for seismic node
pub mod test_utils {
    use super::*;
    use alloy_consensus::{SignableTransaction, TypedTransaction};
    use alloy_dyn_abi::TypedData;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{aliases::U96, hex_literal, Address, Bytes, PrimitiveSignature, U256};
    use alloy_rpc_types::{Block, Header, Transaction, TransactionInput, TransactionReceipt};
    use core::str::FromStr;
    use enr::EnrKey;
    use jsonrpsee::http_client::HttpClient;
    use k256::ecdsa::SigningKey;
    use reth_e2e_test_utils::transaction::TransactionTestContext;
    use reth_enclave::MockEnclaveServer;
    use reth_primitives::TransactionSigned;
    use reth_rpc_eth_api::EthApiClient;
    use secp256k1::SECP256K1;
    use seismic_alloy_consensus::{TxSeismic, TxSeismicElements, TypedDataRequest};

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

    /// Get an unsigned seismic transaction request
    pub async fn get_unsigned_seismic_tx_request(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        plaintext: Bytes,
    ) -> TransactionRequest {
        TransactionRequest {
            from: Some(sk_wallet.address()),
            nonce: Some(nonce),
            value: Some(U256::from(0)),
            to: Some(to),
            gas: Some(6000000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(client_encrypt(&plaintext)), data: None },
            transaction_type: Some(TxSeismic::TX_TYPE),
            // seismic_elements: Some(get_seismic_elements()), TODO:fix
            ..Default::default()
        }
    }

    /// Create a seismic transaction
    pub async fn get_signed_seismic_tx_bytes(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        plaintext: Bytes,
    ) -> Bytes {
        let tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, plaintext).await;
        let signed = TransactionTestContext::sign_tx(sk_wallet.clone(), tx).await;
        <TxEnvelope as Encodable2718>::encoded_2718(&signed).into()
    }

    /// Get an unsigned seismic transaction typed data
    pub async fn get_unsigned_seismic_tx_typed_data(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        decrypted_input: Bytes,
    ) -> TypedData {
        let tx_request =
            get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, decrypted_input).await;
        let typed_tx = tx_request.build_consensus_tx().unwrap();
        match typed_tx {
            // TypedTransaction::Seismic(seismic) => seismic.eip712_to_type_data(),// TODO:fix
            _ => panic!("Typed transaction is not a seismic transaction"),
        }
    }

    /// Create a seismic transaction with typed data
    pub async fn get_signed_seismic_tx_typed_data(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        plaintext: Bytes,
    ) -> TypedDataRequest {
        let tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, plaintext).await;
        // tx.seismic_elements.unwrap().message_version = 2; TODO:fix
        let signed = TransactionTestContext::sign_tx(sk_wallet.clone(), tx).await;

        match signed {
            // Seismic(tx) => tx.into(), TODO:fix
            _ => panic!("Signed transaction is not a seismic transaction"),
        }
    }

    /// Get the network public key
    pub fn get_network_public_key() -> PublicKey {
        MockEnclaveServer::get_public_key()
    }

    /// Encrypt plaintext using network public key and client private key
    pub fn get_ciphertext() -> Bytes {
        let encrypted_data = client_encrypt(&get_plaintext());
        encrypted_data
    }

    /// Encrypt plaintext using network public key and client private key
    pub fn client_encrypt(plaintext: &Bytes) -> Bytes {
        get_seismic_elements()
            .client_encrypt(plaintext, &get_network_public_key(), &get_encryption_private_key())
            .unwrap()
    }

    /// Decrypt ciphertext using network public key and client private key
    pub fn client_decrypt(ciphertext: &Bytes) -> Bytes {
        get_seismic_elements()
            .client_decrypt(ciphertext, &get_network_public_key(), &get_encryption_private_key())
            .unwrap()
    }

    /// Get the encryption private key
    pub fn get_encryption_private_key() -> SecretKey {
        let private_key_bytes =
            hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        SecretKey::from_slice(&private_key_bytes).expect("Invalid private key")
    }

    /// Get the encryption nonce
    pub fn get_encryption_nonce() -> U96 {
        U96::MAX
    }

    /// Get the seismic elements
    pub fn get_seismic_elements() -> TxSeismicElements {
        TxSeismicElements {
            encryption_pubkey: get_encryption_private_key().public_key(SECP256K1),
            encryption_nonce: get_encryption_nonce(),
            message_version: 0,
        }
    }

    /// Get a wrong private key
    pub fn get_wrong_private_key() -> SecretKey {
        let private_key_bytes =
            hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1e");
        SecretKey::from_slice(&private_key_bytes).expect("Invalid private key")
    }

    /// Get the signing private key
    pub fn get_signing_private_key() -> SigningKey {
        let private_key_bytes =
            hex_literal::hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let signing_key =
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
        signing_key
    }

    /// Get the plaintext for a seismic transaction
    pub fn get_plaintext() -> Bytes {
        Bytes::from_str("24a7f0b7000000000000000000000000000000000000000000000000000000000000000b")
            .unwrap()
    }

    /// Get a seismic transaction
    pub fn get_seismic_tx() -> TxSeismic {
        let ciphertext = get_ciphertext();
        TxSeismic {
            chain_id: 1337,
            nonce: 1,
            gas_price: 20000000000,
            gas_limit: 210000,
            to: alloy_primitives::TxKind::Call(
                Address::from_str("0x5fbdb2315678afecb367f032d93f642f64180aa3").unwrap(),
            ),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(&ciphertext),
            seismic_elements: get_seismic_elements(),
        }
    }

    /// Get the encoding of a signed seismic transaction
    pub fn get_signed_seismic_tx_encoding() -> Vec<u8> {
        let signed_tx = get_signed_seismic_tx();
        let mut encoding = Vec::new();

        signed_tx.encode_2718(&mut encoding);
        encoding
    }

    /// Sign a seismic transaction
    pub fn sign_seismic_tx(tx: &TxSeismic) -> PrimitiveSignature {
        let _signature = get_signing_private_key()
            .clone()
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .expect("Failed to sign");

        let recoverid = _signature.1;
        let _signature = _signature.0;

        let signature = PrimitiveSignature::new(
            U256::from_be_slice(_signature.r().to_bytes().as_slice()),
            U256::from_be_slice(_signature.s().to_bytes().as_slice()),
            recoverid.is_y_odd(),
        );

        signature
    }

    /// Get a signed seismic transaction
    pub fn get_signed_seismic_tx() -> TransactionSigned {
        let tx = get_seismic_tx();
        let signature = sign_seismic_tx(&tx);
        // SignableTransaction::into_signed(tx, signature).into()
        todo!()
    }
}
