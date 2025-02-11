use alloy_consensus::{TxEnvelope, TxEnvelope::Seismic};
use alloy_primitives::{Address, TxKind, B256};
use alloy_rpc_types::engine::PayloadAttributes;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use reth_chainspec::SEISMIC_DEV;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_tee::{
    mock::{MockTeeServer, MockWallet},
    WalletAPI,
};
use secp256k1::{PublicKey, SecretKey};
use serde_json::Value;
use std::{net::UdpSocket, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc,
    task,
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
            .arg("--tee.mock-server")
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

                        if stdout_line.contains("starting mock tee server") && !sent {
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

/// Start the mock tee server
pub async fn start_mock_tee_server_with_default_ports() {
    let _ = task::spawn(async {
        let tee_server = MockTeeServer::new("127.0.0.1:7878");
        tee_server.run().await.map_err(|_| eyre::Error::msg("tee server failed"))
    });
}

/// Helper function to create a new eth payload attributes
pub fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
        target_blobs_per_block: None,
        max_blobs_per_block: None,
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Test utils for seismic node
pub mod test_utils {
    use std::{fs::File, sync::Arc};

    use super::*;
    use alloy_consensus::{SignableTransaction, TxSeismic, TypedTransaction};
    use alloy_dyn_abi::TypedData;
    use alloy_eips::{eip2718::Encodable2718, eip712::TypedDataRequest};
    use alloy_network::TransactionBuilder;
    use alloy_primitives::{hex_literal, Address, Bytes, FixedBytes, PrimitiveSignature, U256};
    use alloy_rpc_types::{Block, Header, Transaction, TransactionInput, TransactionReceipt};
    use core::str::FromStr;
    use enr::EnrKey;
    use jsonrpsee::http_client::HttpClient;
    use k256::ecdsa::SigningKey;
    use reth_chainspec::{ChainSpec, MAINNET};
    use reth_e2e_test_utils::transaction::TransactionTestContext;
    use reth_node_ethereum::EthEvmConfig;
    use reth_primitives::TransactionSigned;
    use reth_rpc_eth_api::EthApiClient;
    use reth_tee::{TeeHttpClient, TEE_DEFAULT_ENDPOINT_ADDR};
    use secp256k1::ecdh::SharedSecret;
    use seismic_enclave::{aes_encrypt, derive_aes_key, get_sample_secp256k1_pk};
    use serde::{Deserialize, Serialize};

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

    /// Decrypt ciphertext using network public key and client private key
    pub async fn client_decrypt(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        ciphertext: &Bytes,
    ) -> Bytes {
        let sk = SecretKey::from_slice(&sk_wallet.credential().to_bytes())
            .expect("32 bytes, within curve order");
        let tee_wallet = MockWallet {};
        let decrypted_output =
            <MockWallet as WalletAPI>::decrypt(&tee_wallet, ciphertext.to_vec(), nonce, &sk)
                .unwrap();
        Bytes::from(decrypted_output)
    }

    /// Encrypt plaintext using network public key and client private key
    pub async fn client_encrypt(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        plaintext: &Bytes,
    ) -> Bytes {
        let sk = SecretKey::from_slice(&sk_wallet.credential().to_bytes())
            .expect("32 bytes, within curve order");
        let tee_wallet = MockWallet {};
        let encrypted_output =
            <MockWallet as WalletAPI>::encrypt(&tee_wallet, plaintext.to_vec(), nonce, &sk)
                .unwrap();
        Bytes::from(encrypted_output)
    }

    /// Get the encryption public key
    pub fn get_encryption_pubkey(sk_wallet: &PrivateKeySigner) -> PublicKey {
        let sk = SecretKey::from_slice(&sk_wallet.credential().to_bytes())
            .expect("32 bytes, within curve order");
        PublicKey::from_secret_key_global(&sk)
    }

    /// Get an unsigned seismic transaction request
    pub async fn get_unsigned_seismic_tx_request(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        decrypted_input: Bytes,
    ) -> TransactionRequest {
        let encrypted_input = client_encrypt(sk_wallet, nonce, &decrypted_input).await;
        println!("nonce: {}", nonce);

        let encryption_pubkey = get_encryption_pubkey(sk_wallet);
        TransactionRequest {
            from: Some(sk_wallet.address()),
            nonce: Some(nonce),
            value: Some(U256::from(0)),
            to: Some(to),
            gas: Some(6000000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(Bytes::from(encrypted_input)), data: None },
            transaction_type: Some(TxSeismic::TX_TYPE),
            encryption_pubkey: Some(alloy_consensus::transaction::EncryptionPublicKey::from(
                encryption_pubkey.serialize(),
            )),
            ..Default::default()
        }
    }

    /// Create a seismic transaction
    pub async fn get_signed_seismic_tx_bytes(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        decrypted_input: Bytes,
    ) -> Bytes {
        let tx =
            get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, decrypted_input).await;
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
            TypedTransaction::Seismic(seismic) => seismic.eip712_to_type_data(),
            _ => panic!("Typed transaction is not a seismic transaction"),
        }
    }

    /// Create a seismic transaction with typed data
    pub async fn get_signed_seismic_tx_typed_data(
        sk_wallet: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        chain_id: u64,
        decrypted_input: Bytes,
    ) -> TypedDataRequest {
        let tx = get_unsigned_seismic_tx_request(sk_wallet, nonce, to, chain_id, decrypted_input)
            .await
            .with_message_version(2); //message version makes it a typed data
        let signed = TransactionTestContext::sign_tx(sk_wallet.clone(), tx).await;

        match signed {
            Seismic(tx) => tx.into(),
            _ => panic!("Signed transaction is not a seismic transaction"),
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    /// Integration test context
    pub struct IntegrationTestContext {
        /// The deploy transaction
        pub deploy_tx: String,
        /// The contract address
        pub contract: String,
        /// The contract code
        pub code: String,
        /// The tx hashes
        pub tx_hashes: Vec<String>,
        /// The signed calls
        pub signed_calls: Vec<String>,
        /// The raw transactions
        pub raw_txs: Vec<String>,
        /// The encrypted outputs
        pub encrypted_outputs: Vec<String>,
    }

    impl IntegrationTestContext {
        const IT_TX_FILEPATH: &'static str = "tests/seismic-data/it-tx.json";

        /// Create a new integration test context
        pub fn new(deploy_tx: &Bytes) -> IntegrationTestContext {
            IntegrationTestContext {
                deploy_tx: Self::fmt(deploy_tx),
                contract: "".into(),
                code: "".into(),
                tx_hashes: vec![],
                signed_calls: vec![],
                raw_txs: vec![],
                encrypted_outputs: vec![],
            }
        }

        /// Format a bytes array as a hex string
        fn fmt(bytes: &Bytes) -> String {
            format!("{:0x}", bytes)
        }

        /// Add a contract address to the integration test context
        pub fn contract(&mut self, addr: &Address) {
            self.contract = format!("{:0x}", addr);
        }

        /// Add a contract code to the integration test context
        pub fn code(&mut self, code: &Bytes) {
            self.code = Self::fmt(code);
        }

        /// Add a tx hash to the integration test context
        pub fn tx_hash(&mut self, bytes: &FixedBytes<32>) {
            self.tx_hashes.push(format!("0x{:0x}", bytes))
        }

        /// Add a signed call to the integration test context
        pub fn signed_call(&mut self, bytes: &Bytes) {
            self.signed_calls.push(Self::fmt(bytes));
        }

        /// Add a raw transaction to the integration test context
        pub fn raw_tx(&mut self, bytes: &Bytes) {
            self.raw_txs.push(Self::fmt(bytes));
        }

        /// Add an encrypted output to the integration test context
        pub fn encrypted_output(&mut self, bytes: &Bytes) {
            self.encrypted_outputs.push(Self::fmt(bytes));
        }

        /// Load the integration test context from a file
        pub fn load() -> IntegrationTestContext {
            let file = File::open(Self::IT_TX_FILEPATH).unwrap();
            serde_json::from_reader(file).unwrap()
        }

        /// Write the integration test context to a file
        pub fn write(&self) {
            let file = File::create(Self::IT_TX_FILEPATH).unwrap();
            serde_json::to_writer_pretty(file, &self).unwrap();
        }

        /// This is here to prevent us from mistakenly re-writing
        /// the expected test values while the basic integration test runs
        /// If we are careful about setting `REWRITE_IT_TX`,
        /// this would be unneccessary, but it will definitely happen lol
        pub fn should_rewrite_it() -> bool {
            // Check if SEISMIC_CI is present in the environment
            if std::env::var("SEISMIC_CI").is_ok() {
                false
            } else {
                true
            }
        }
    }

    #[derive(Debug)]
    /// Artificats for unit tests
    pub struct UnitTestContext;
    impl UnitTestContext {
        /// Encrypt plaintext using network public key and client private key
        pub fn get_client_side_encryption() -> Vec<u8> {
            let ecdh_sk = get_sample_secp256k1_pk();
            let signing_key_bytes = Self::get_encryption_private_key().to_bytes();
            let signing_key_secp256k1 =
                secp256k1::SecretKey::from_slice(&signing_key_bytes).expect("Invalid secret key");
            let shared_secret = SharedSecret::new(&ecdh_sk, &signing_key_secp256k1);

            let aes_key = derive_aes_key(&shared_secret).unwrap();
            let encrypted_data =
                aes_encrypt(&aes_key, Self::get_plaintext().as_slice(), 1).unwrap();
            encrypted_data
        }

        /// Get the test tee endpoint
        pub fn get_test_tee_endpoint() -> u16 {
            let mut found_port = 7878;
            for p in 1..65535 {
                let address = format!("127.0.0.1:{}", p);
                if let Ok(_socket) = UdpSocket::bind(&address) {
                    found_port = p;
                    println!("✅ Port {} is available for TEE server", p);
                    break;
                }
            }
            found_port
        }

        /// Get the test tee client
        pub fn get_test_tee_client() -> TeeHttpClient {
            TeeHttpClient::new(format!(
                "http://{}:{}",
                TEE_DEFAULT_ENDPOINT_ADDR,
                Self::get_test_tee_endpoint()
            ))
        }

        /// Start the mock tee server
        pub async fn start_mock_tee_server() {
            let _ = task::spawn(async move {
                let tee_server =
                    MockTeeServer::new(&format!("127.0.0.1:{}", Self::get_test_tee_endpoint()));
                tee_server.run().await.map_err(|_| eyre::Error::msg("tee server failed"))
            });
        }

        /// Get the chain spec
        pub fn get_chain_spec() -> Arc<ChainSpec> {
            MAINNET.clone()
        }

        /// Get the evm config
        pub fn get_evm_config() -> EthEvmConfig {
            let tee_client = Self::get_test_tee_client();
            EthEvmConfig::new_with_tee_client(Self::get_chain_spec(), tee_client)
        }

        /// Get the encryption private key
        pub fn get_encryption_private_key() -> SigningKey {
            let private_key_bytes = hex_literal::hex!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            );
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key")
        }

        /// Get a wrong private key
        pub fn get_wrong_private_key() -> SigningKey {
            let private_key_bytes = hex_literal::hex!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1e"
            );
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key")
        }

        /// Get the signing private key
        pub fn get_signing_private_key() -> SigningKey {
            let private_key_bytes = hex_literal::hex!(
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            );
            let signing_key =
                SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
            signing_key
        }

        /// Get the plaintext for a seismic transaction
        pub fn get_plaintext() -> Vec<u8> {
            hex_literal::hex!(
                "24a7f0b7000000000000000000000000000000000000000000000000000000000000000b"
            )
            .to_vec()
        }

        /// Get a seismic transaction
        pub fn get_seismic_tx() -> TxSeismic {
            let ciphertext = Self::get_client_side_encryption();
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
                encryption_pubkey: FixedBytes::from_slice(
                    &Self::get_encryption_private_key().public().to_sec1_bytes(),
                ),
                message_version: 0,
            }
        }

        /// Get the encoding of a signed seismic transaction
        pub fn get_signed_seismic_tx_encoding() -> Vec<u8> {
            let signed_tx = Self::get_signed_seismic_tx();
            let mut encoding = Vec::new();

            signed_tx.encode_2718(&mut encoding);
            encoding
        }

        /// Sign a seismic transaction
        pub fn sign_seismic_tx(tx: &TxSeismic) -> PrimitiveSignature {
            let _signature = Self::get_signing_private_key()
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
            let tx = Self::get_seismic_tx();
            let signature = Self::sign_seismic_tx(&tx);
            SignableTransaction::into_signed(tx, signature).into()
        }
    }
}
