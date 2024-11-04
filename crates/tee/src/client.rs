//! This module provides functionality for encryption and decryption
//! using a Trusted Execution Environment (TEE) client.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr
};

use crate::types::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

use aes_gcm::{Aes256Gcm, Key};
use alloy_rlp::{Decodable, Encodable, Error};
use hkdf::Hkdf;
use hyper::Response;
use reqwest::Client;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub const TEE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
pub const TEE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Trait for the API of the TEE client
pub trait TeeAPI {
    /// Encrypts the given data using the public key included in the request
    /// and the private key of the TEE server
    async fn io_encrypt(
        &self,
        payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error>;

    /// Decrypts the given data using the public key included in the request
    /// and the private key of the TEE server
    async fn io_decrypt(
        &self,
        payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error>;
}

pub trait WalletAPI {
    fn encrypt(
        &self,
        data: &Vec<u8>,
        nonce: u64,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error>;
}

/// An implementation of the TEE client API that
/// makes HTTP requests to the TEE server
#[derive(Debug, Clone)]
pub struct TeeHttpClient {
    /// url of the TEE server
    pub base_url: String,
    /// HTTP client for making requests
    pub client: Client,
}

impl Default for TeeHttpClient {
    fn default() -> Self {
        Self {
            base_url: format!("http://{}:{}", TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT),
            client: Client::new(),
        }
    }
}

impl TeeHttpClient {
    /// Creates a new instance of the TEE client
    pub fn new(base_url: String) -> Self {
        Self { base_url, client: Client::new() }
    }

    /// Creates a new instance of the TEE client
    pub fn new_from_addr_port(addr: IpAddr, port: u16) -> Self {
        Self {
            base_url: format!("http://{}:{}", addr, port),
            client: Client::new(),
        }
    }

    pub fn new_from_addr(addr: &SocketAddr) -> Self {
        let base_url = format!("http://{}", addr);
        Self {
            base_url,
            client: Client::new(),
        }
    }
}

impl TeeAPI for TeeHttpClient {
    async fn io_encrypt(
        &self,
        payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;

        // Using reqwest's Client to send a POST request
        let response = self
            .client
            .post(format!("{}/tx_io/encrypt", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        // Extract the response body as bytes
        let body: Vec<u8> = response.bytes().await?.to_vec();

        // Parse the response body into the IoEncryptionResponse struct
        let enc_response: IoEncryptionResponse = serde_json::from_slice(&body)?;

        Ok(enc_response)
    }

    async fn io_decrypt(
        &self,
        payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;

        // Using reqwest's Client to send a POST request
        let response = self
            .client
            .post(format!("{}/tx_io/decrypt", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        // Extract the response body as bytes
        let body: Vec<u8> = response.bytes().await?.to_vec();

        // Parse the response body into the IoDecryptionResponse struct
        let dec_response: IoDecryptionResponse = serde_json::from_slice(&body)?;

        Ok(dec_response)
    }
}

/// Tee error type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TeeError {
    /// tee encryption fails
    EncryptionError,
    /// tee decryption fails
    DecryptionError,
    /// encoding or decoding
    CodingError(alloy_rlp::Error),
    /// Custom error.
    Custom(&'static str),
}

/// Blocking decrypt function call to contact TeeAPI
pub fn decrypt<I: Encodable + Decodable, T: TeeAPI>(
    tee_client: &T,
    msg_sender: PublicKey,
    data: Vec<u8>,
    nonce: u64,
) -> Result<I, TeeError> {
    let payload = IoDecryptionRequest { msg_sender, data, nonce };
    let IoDecryptionResponse { decrypted_data } = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tee_client.io_decrypt(payload))
    })
    .map_err(|_| TeeError::EncryptionError)?;
    I::decode(&mut &decrypted_data[..]).map_err(|err| TeeError::CodingError(err))
}

/// Blocking encrypt function call to contact TeeAPI
pub fn encrypt<I: Encodable + Decodable, T: TeeAPI>(
    tee_client: &T,
    msg_sender: PublicKey,
    plaintext: I,
    nonce: u64,
) -> Result<Vec<u8>, TeeError> {
    let mut data = Vec::new();
    plaintext.encode(&mut data);
    let payload = IoEncryptionRequest { msg_sender, data, nonce };
    let IoEncryptionResponse { encrypted_data } = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tee_client.io_encrypt(payload))
    })
    .map_err(|_| TeeError::DecryptionError)?;
    Ok(encrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use secp256k1::PublicKey;
    use serde_json::json;
    use std::{
        str::FromStr,
        sync::{Arc, Mutex},
    };
    use tokio::spawn;
    use warp::Filter;

    #[tokio::test]
    async fn test_io_encrypt() {
        let plaintext = vec![72, 101, 108, 108, 111]; // Example plaintext
        let ciphertext = vec![
            5, 119, 55, 108, 84, 7, 255, 70, 233, 138, 125, 130, 228, 149, 140, 144, 126, 138, 10,
            215, 164, 74,
        ]; // Example encrypted data
        let mock_enc_response = IoEncryptionResponse { encrypted_data: ciphertext.clone() };

        let mock_dec_response = IoDecryptionResponse { decrypted_data: plaintext.clone() };

        let mock_response = json!({
            "/tx_io/encrypt": serde_json::to_string(&mock_enc_response).unwrap(),
            "/tx_io/decrypt": serde_json::to_string(&mock_dec_response).unwrap(),
        });

        let mock_response = Arc::new(Mutex::new(mock_response));

        // Use warp to create the mock server
        let mock_service =
            warp::any().and(warp::path::full()).map(move |path: warp::filters::path::FullPath| {
                let mock_response = mock_response.lock().unwrap();
                let response_body =
                    mock_response.get(path.as_str()).unwrap().as_str().unwrap().to_string();
                warp::reply::json(
                    &serde_json::from_str::<serde_json::Value>(&response_body).unwrap(),
                )
            });

        // Start warp server
        let (addr, server) =
            warp::serve(mock_service).bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            });

        let server_addr = addr;
        let _ = spawn(server);

        let client = Client::new();
        let base_url = format!("http://{}", server_addr);
        let tee_client = TeeHttpClient { base_url: base_url.clone(), client: client.clone() };

        // Original encryption request
        let encryption_request = IoEncryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: plaintext.clone(),
            nonce: 12345678,
        };

        // Test encrypt
        let enc_response = tee_client.io_encrypt(encryption_request).await.unwrap();
        assert_eq!(enc_response.encrypted_data, ciphertext);

        // Original decryption request
        let payload = IoDecryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: enc_response.encrypted_data,
            nonce: 12345678,
        };

        // Test decrypt
        let dec_response = tee_client.io_decrypt(payload.clone()).await.unwrap();
        assert_eq!(dec_response.decrypted_data, plaintext);
    }

}
