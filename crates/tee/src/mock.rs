use aes_gcm::{Aes256Gcm, Key};
use anyhow::{anyhow, Result};
use hyper::{body::to_bytes, Body, Request, Response, Server, StatusCode};
use routerify::{RequestInfo, Router, RouterService};
use secp256k1::ecdh::SharedSecret;
use std::{convert::Infallible, net::SocketAddr, str::FromStr};
use tracing::{debug, error, info};

use crate::{TeeAPI, WalletAPI};
use tee_service_api::{
    crypto::{
        aes_decrypt, aes_encrypt, derive_aes_key, get_sample_secp256k1_pk, get_sample_secp256k1_sk,
    },
    errors::{invalid_ciphertext_resp, invalid_json_body_resp},
    request_types::tx_io::{
        IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
    },
};

/// MockTeeServer is a mock implementation of a TEE (Trusted Execution Environment) server.
/// It provides endpoints for encrypting and decrypting data using AES-256-GCM encryption.
#[derive(Debug)]
pub struct MockTeeServer {
    /// The address on which the server is running
    addr: SocketAddr,
}

async fn error_handler(err: routerify::RouteError, _: RequestInfo) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {}", err)))
        .unwrap()
}

impl MockTeeServer {
    /// create a new tee mock server that runs on the given address
    pub fn new(addr: &str) -> Self {
        MockTeeServer { addr: SocketAddr::from_str(addr).unwrap() }
    }

    /// start the mock tee server
    pub async fn run(&self) -> Result<()> {
        let router = Router::builder()
            .post("/tx_io/encrypt", MockTeeServer::handle_io_encrypt)
            .post("/tx_io/decrypt", MockTeeServer::handle_io_decrypt)
            .err_handler_with_info(error_handler)
            .build()
            .unwrap();

        let service = RouterService::new(router).unwrap();
        let server = Server::bind(&self.addr).serve(service);

        info!(target: "reth::server", "Starting Hyper server on {}", self.addr);

        match server.await {
            Ok(_) => {
                info!(target: "reth::server", "Hyper server stopped gracefully.");
                Ok(())
            }
            Err(err) => {
                error!(target: "reth::server", "Hyper server failed: {}", err);
                Err(anyhow::anyhow!("Hyper server failed to start: {}", err))
            }
        }
    }

    /// handle the io_encrypt endpoint
    async fn handle_io_encrypt(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body_bytes = to_bytes(req.into_body()).await.unwrap();
        let payload: IoEncryptionRequest = match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(invalid_json_body_resp()),
        };
        debug!(target: "reth::mock_server", "Received request: {:?}", payload);

        let client = MockTeeClient {};
        match client.tx_io_encrypt(payload).await {
            Ok(response) => {
                Ok(Response::new(Body::from(serde_json::to_string(&response).unwrap())))
            }
            Err(e) => Ok(invalid_ciphertext_resp(e)),
        }
    }

    /// handle the io_decrypt endpoint
    async fn handle_io_decrypt(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body_bytes = to_bytes(req.into_body()).await.unwrap();
        let payload: IoDecryptionRequest = match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(invalid_json_body_resp()),
        };
        debug!(target: "reth::mock_server", "Received request: {:?}", payload);

        let client = MockTeeClient {};
        match client.tx_io_decrypt(payload).await {
            Ok(response) => {
                Ok(Response::new(Body::from(serde_json::to_string(&response).unwrap())))
            }
            Err(e) => Ok(invalid_ciphertext_resp(e)),
        }
    }
}

/// MockTeeClient is a mock implementation of a TEE (Trusted Execution Environment) client.
#[derive(Debug)]
pub struct MockTeeClient {}
impl TeeAPI for MockTeeClient {
    async fn tx_io_encrypt(
        &self,
        payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error> {
        // load key and decrypt data
        let ecdh_sk = get_sample_secp256k1_sk();
        let shared_secret = SharedSecret::new(&payload.key, &ecdh_sk);

        let aes_key = derive_aes_key(&shared_secret)
            .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
        let encrypted_data = aes_encrypt(&aes_key, &payload.data, payload.nonce)?;

        Ok(IoEncryptionResponse { encrypted_data })
    }

    async fn tx_io_decrypt(
        &self,
        payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error> {
        // load key and decrypt data
        let ecdh_sk = get_sample_secp256k1_sk();
        let shared_secret = SharedSecret::new(&payload.key, &ecdh_sk);

        debug!(target: "reth::mock_client", ?payload);

        let aes_key = derive_aes_key(&shared_secret)
            .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
        let decrypted_data = aes_decrypt(&aes_key, &payload.data, payload.nonce)?;

        Ok(IoDecryptionResponse { decrypted_data })
    }
}

/// MockWallet is the wallet that has tee public key to encrypt transactions
#[derive(Debug)]
pub struct MockWallet {}

impl MockWallet {
    fn generate_aes_key(private_key: &secp256k1::SecretKey) -> Result<Key<Aes256Gcm>> {
        let ecdh_pk = get_sample_secp256k1_pk();
        let shared_secret = SharedSecret::new(&ecdh_pk, private_key);
        let aes_key = derive_aes_key(&shared_secret)
            .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
        Ok(aes_key)
    }
}

impl WalletAPI for MockWallet {
    fn encrypt(
        &self,
        data: Vec<u8>,
        nonce: u64,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let aes_key = MockWallet::generate_aes_key(private_key)?;
        let encrypted_data = aes_encrypt(&aes_key, &data, nonce)?;
        Ok(encrypted_data)
    }

    fn decrypt(
        &self,
        data: Vec<u8>,
        nonce: u64,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let aes_key = MockWallet::generate_aes_key(private_key)?;
        let decrypted_data = aes_decrypt(&aes_key, &data, nonce)?;
        Ok(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::OsRng;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use tee_service_api::http_client::TeeHttpClient;
    use tokio::task;

    #[tokio::test]
    async fn test_encrypt_decrypt_mock_client_wallet() {
        // Generate a new secp256k1 key pair
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let wallet_secret_key = SecretKey::new(&mut rng);
        let wallet_public_key = PublicKey::from_secret_key(&secp, &wallet_secret_key);

        let plaintext = vec![1, 2, 3];
        let nonce: u64 = 10;
        let mock_wallet = MockWallet {};
        let cyphertext = mock_wallet.encrypt(plaintext.clone(), nonce, &wallet_secret_key).unwrap();

        // Original encryption request
        let decryption_request =
            IoDecryptionRequest { key: wallet_public_key, data: cyphertext.clone(), nonce };

        let tee = MockTeeClient {};
        let start_time = std::time::Instant::now();

        for _ in 0..100 {
            let dec_response = tee.tx_io_decrypt(decryption_request.clone()).await.unwrap();
            assert!(dec_response.decrypted_data == plaintext);
        }

        let end_time = std::time::Instant::now();
        let duration = end_time.duration_since(start_time);
        println!("Time taken for decryption: {:?}", duration);
    }

    #[tokio::test]
    async fn test_mock_tee_server_encrypt_decrypt() {
        // Start the MockTeeServer in a separate task
        let addr = SocketAddr::from_str("127.0.0.1:7878").unwrap();

        // Start the MockTeeServer in a separate task
        let server_task = task::spawn(async move {
            let server = MockTeeServer { addr };
            server.run().await.unwrap();
        });

        // Give the server some time to start
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Create a client to send requests to the server
        let tee_client = TeeHttpClient::new_from_addr(&addr);

        // Generate a new secp256k1 key pair
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let wallet_secret_key = SecretKey::new(&mut rng);
        let wallet_public_key = PublicKey::from_secret_key(&secp, &wallet_secret_key);

        let plaintext = vec![1, 2, 3];
        let nonce: u64 = 10;

        // Create an encryption request
        let encryption_request =
            IoEncryptionRequest { key: wallet_public_key, data: plaintext.clone(), nonce };

        // Send the encryption request
        let encryption_response = match tee_client.tx_io_encrypt(encryption_request).await {
            Ok(response) => response,
            Err(_) => {
                return;
            }
        };

        // Create a decryption request
        let decryption_request = IoDecryptionRequest {
            key: wallet_public_key,
            data: encryption_response.encrypted_data,
            nonce,
        };

        // Send the decryption request
        let decryption_response = tee_client.tx_io_decrypt(decryption_request).await.unwrap();

        assert_eq!(decryption_response.decrypted_data, plaintext);

        // Stop the server task
        server_task.abort();
    }
}
