use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use alloy_rlp::{Decodable, Encodable};
use anyhow::{anyhow, Error, Result};
use hkdf::Hkdf;
use hyper::{body::to_bytes, Body, Request, Response, Server, StatusCode};
use once_cell::sync::Lazy;
use routerify::{ext::RequestExt, Middleware, RequestInfo, Router, RouterService};
use secp256k1::{ecdh::SharedSecret, Keypair, SecretKey};
use serde_json::json;
use sha2::Sha256;
use std::{convert::Infallible, net::SocketAddr, str::FromStr};

use crate::{
    client::{TeeAPI, TeeError, WalletAPI, TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT},
    types::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

pub struct MockTeeServer {
    addr: SocketAddr,
}

impl MockTeeServer {
    pub fn new(addr: &str) -> Self {
        MockTeeServer { addr: SocketAddr::from_str(addr).unwrap() }
    }
    pub async fn run(&self) -> Result<()> {
        let router = Router::builder()
            .post("/tx_io/encrypt", MockTeeServer::handle_io_encrypt)
            .post("/tx_io/decrypt", MockTeeServer::handle_io_decrypt)
            .build()
            .unwrap();

        let service = RouterService::new(router).unwrap();

        let server = Server::bind(&self.addr).serve(service);

        println!("MockTeeServer running on http://{}", self.addr);
        server.await?;
        Ok(())
    }

    async fn handle_io_encrypt(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body_bytes = to_bytes(req.into_body()).await.unwrap();
        let payload: IoEncryptionRequest = match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(invalid_json_body_resp()),
        };

        let client = MockTeeClient {};
        match client.io_encrypt(payload).await {
            Ok(response) => {
                Ok(Response::new(Body::from(serde_json::to_string(&response).unwrap())))
            }
            Err(e) => Ok(invalid_ciphertext_resp(e)),
        }
    }

    async fn handle_io_decrypt(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body_bytes = to_bytes(req.into_body()).await.unwrap();
        let payload: IoDecryptionRequest = match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(invalid_json_body_resp()),
        };

        let client = MockTeeClient {};
        match client.io_decrypt(payload).await {
            Ok(response) => {
                Ok(Response::new(Body::from(serde_json::to_string(&response).unwrap())))
            }
            Err(e) => Ok(invalid_ciphertext_resp(e)),
        }
    }
}

pub struct MockTeeClient {}
impl TeeAPI for MockTeeClient {
    async fn io_encrypt(
        &self,
        payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error> {
        // load key and decrypt data
        let ecdh_sk = get_sample_secp256k1_sk();
        let shared_secret = SharedSecret::new(&payload.msg_sender, &ecdh_sk);

        let aes_key = derive_aes_key(&shared_secret)
            .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
        let encrypted_data = aes_encrypt(&aes_key, &payload.data, payload.nonce);

        Ok(IoEncryptionResponse { encrypted_data })
    }

    async fn io_decrypt(
        &self,
        payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error> {
        // load key and decrypt data
        let ecdh_sk = get_sample_secp256k1_sk();
        let shared_secret = SharedSecret::new(&payload.msg_sender, &ecdh_sk);

        let aes_key = derive_aes_key(&shared_secret)
            .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
        let decrypted_data = aes_decrypt(&aes_key, &payload.data, payload.nonce)
            .map_err(|e| anyhow!("Decryption error: {:?}", e))?;

        Ok(IoDecryptionResponse { decrypted_data })
    }
}

pub struct MockWallet {}
impl WalletAPI for MockWallet {
    fn encrypt(
        &self,
        data: &Vec<u8>,
        nonce: u64,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let ecdh_pk = get_sample_secp256k1_pk();
        let shared_secret = SharedSecret::new(&ecdh_pk, private_key);

        let aes_key = derive_aes_key(&shared_secret)
            .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
        let encrypted_data = aes_encrypt(&aes_key, &data, nonce);
        Ok(encrypted_data)
    }
}

pub fn derive_aes_key(shared_secret: &SharedSecret) -> Result<Key<Aes256Gcm>, hkdf::InvalidLength> {
    // Initialize HKDF with SHA-256
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.secret_bytes());

    // Output a 32-byte key for AES-256
    let mut okm = [0u8; 32];
    hk.expand(b"aes-gcm key", &mut okm)?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

pub fn aes_encrypt<T: Encodable>(key: &Key<Aes256Gcm>, plaintext: &T, nonce: u64) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let nonce = u64_to_generic_u8_array(nonce);

    // convert the encodable object to a Vec<u8>
    let mut buf = Vec::new();
    plaintext.encode(&mut buf);

    // encrypt the Vec<u8>
    cipher
        .encrypt(&nonce, buf.as_ref())
        .unwrap_or_else(|err| panic!("Encryption failed: {:?}", err))
}

pub fn aes_decrypt<T>(
    key: &Key<Aes256Gcm>,
    ciphertext: &[u8],
    nonce: u64,
) -> Result<T, anyhow::Error>
where
    T: Decodable,
{
    let cipher = Aes256Gcm::new(key);
    let nonce = u64_to_generic_u8_array(nonce);

    // recover the plaintext byte encoding of the object
    let buf = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("AES decryption failed: {:?}", e))?;

    // recover the object from the byte encoding
    let plaintext =
        T::decode(&mut &buf[..]).map_err(|e| anyhow!("Failed to decode plaintext: {:?}", e))?;

    Ok(plaintext)
}

/// Returns a sample Secp256k1 secret key for testing purposes.
pub fn get_sample_secp256k1_sk() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_str(
        "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
    )
    .unwrap()
}

/// Returns a sample Secp256k1 public key for testing purposes.
pub fn get_sample_secp256k1_pk() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
    )
    .unwrap()
}

fn u64_to_generic_u8_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce_bytes = nonce.to_be_bytes().to_vec();
    let crypto_nonce_size = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();
    nonce_bytes.resize(crypto_nonce_size, 0); // pad to the expected size
    GenericArray::clone_from_slice(&nonce_bytes)
}

/// Returns 400 Bad Request
/// Meant to be used if there is an error while reading the request body
pub fn invalid_req_body_resp() -> Response<Body> {
    let error_response = json!({ "error": "Invalid request body" }).to_string();
    Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(error_response)).unwrap()
}

// Returns 400 Bad Request
// Meant to be used if deserializing the body into a json fails
pub fn invalid_json_body_resp() -> Response<Body> {
    let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
    Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(error_response)).unwrap()
}

// Returns 422 Unprocessable Entity
// Meant to be used if decrypting the ciphertext fails
pub fn invalid_ciphertext_resp(e: Error) -> Response<Body> {
    let error_message = format!("Invalid ciphertext: {}", e); // Use error's Display trait
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::UNPROCESSABLE_ENTITY)
        .body(Body::from(error_response))
        .unwrap()
}

mod tests {

    use crate::{
        client::{TeeHttpClient, TEE_DEFAULT_ENDPOINT_PORT},
        mock::MockTeeServer,
        types::{IoDecryptionRequest, IoEncryptionRequest, IoEncryptionResponse},
    };
    use aes_gcm::aead::OsRng;
    use hyper::{Body, Client, Method, Request, StatusCode};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::{net::SocketAddr, str::FromStr, thread, time::Duration};
    use tokio::{net::TcpListener, runtime::Runtime, task};

    use crate::{
        client::{TeeAPI, WalletAPI},
        mock::{MockTeeClient, MockWallet},
    };

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
        let cyphertext = mock_wallet.encrypt(&plaintext, nonce, &wallet_secret_key).unwrap();

        // Original encryption request
        let decryption_request =
            IoDecryptionRequest { msg_sender: wallet_public_key, data: cyphertext.clone(), nonce };

        let tee = MockTeeClient {};
        let start_time = std::time::Instant::now();

        for _ in 0..100 {
            let dec_response = tee.io_decrypt(decryption_request.clone()).await.unwrap();
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
            IoEncryptionRequest { msg_sender: wallet_public_key, data: plaintext.clone(), nonce };

        // Send the encryption request
        let encryption_response = match tee_client.io_encrypt(encryption_request).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Encryption request failed: {:?}", e);
                return;
            }
        };

        // Create a decryption request
        let decryption_request = IoDecryptionRequest {
            msg_sender: wallet_public_key,
            data: encryption_response.encrypted_data,
            nonce,
        };

        // Send the decryption request
        let decryption_response = tee_client.io_decrypt(decryption_request).await.unwrap();

        assert_eq!(decryption_response.decrypted_data, plaintext);

        // Stop the server task
        server_task.abort();
    }
}
