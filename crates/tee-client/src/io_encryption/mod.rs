//! This module provides functionality for encryption and decryption
//! using a Trusted Execution Environment (TEE) client.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]

mod structs;

use structs::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse};
use reqwest::Client;

/// Trait for the API of the TEE client
pub trait TeeClientAPI {
    /// Encrypts the given data using the public key included in the request
    /// and the private key of the TEE server
    async fn io_encrypt(&self, payload: IoEncryptionRequest) -> Result<IoEncryptionResponse, anyhow::Error>;
    
    /// Decrypts the given data using the public key included in the request
    /// and the private key of the TEE server
    async fn io_decrypt(&self, payload: IoDecryptionRequest) -> Result<IoDecryptionResponse, anyhow::Error>;
}

/// An implementation of the TEE client API that 
/// makes HTTP requests to the TEE server
#[derive(Debug)]
pub struct TeeHttpClient {
    /// url of the TEE server
    pub base_url: String,
    /// HTTP client for making requests
    pub client: Client,
}

impl TeeHttpClient {
    /// Creates a new instance of the TEE client
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
        }
    }
}

impl TeeClientAPI for TeeHttpClient {
    async fn io_encrypt(&self, payload: IoEncryptionRequest) -> Result<IoEncryptionResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
    
        // Using reqwest's Client to send a POST request
        let response = self.client
            .post(format!("{}/io_encrypt", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;
    
        // Extract the response body as bytes
        let body: Vec<u8> = response.bytes().await?.to_vec();
        println!("body: {:?}", body);
    
        // Parse the response body into the IoEncryptionResponse struct
        let enc_response: IoEncryptionResponse = serde_json::from_slice(&body)?;
    
        Ok(enc_response)
    }

    async fn io_decrypt(&self, payload: IoDecryptionRequest) -> Result<IoDecryptionResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
    
        // Using reqwest's Client to send a POST request
        let response = self.client
            .post(format!("{}/io_decrypt", self.base_url))
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


#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::sync::{Arc, Mutex};
    use secp256k1::PublicKey;
    use std::str::FromStr;
    use serde_json::json;
    use tokio::spawn;
    use warp::Filter;

    #[tokio::test]
    async fn test_io_encrypt() {
        let plaintext = vec![72, 101, 108, 108, 111]; // Example plaintext
        let ciphertext = vec![5, 119, 55, 108, 84, 7, 255, 70, 233, 138, 125, 130, 228, 149, 140, 144, 126, 138, 10, 215, 164, 74]; // Example encrypted data
        let mock_enc_response = IoEncryptionResponse {
            encrypted_data: ciphertext.clone(),
        };
        
        let mock_dec_response = IoDecryptionResponse {
            decrypted_data: plaintext.clone(),
        };

        let mock_response = json!({
            "/io_encrypt": serde_json::to_string(&mock_enc_response).unwrap(),
            "/io_decrypt": serde_json::to_string(&mock_dec_response).unwrap(),
        });

        let mock_response = Arc::new(Mutex::new(mock_response));

        // Use warp to create the mock server
        let mock_service = warp::any().and(warp::path::full()).map(move |path: warp::filters::path::FullPath| {
            let mock_response = mock_response.lock().unwrap();
            let response_body = mock_response.get(path.as_str()).unwrap().as_str().unwrap().to_string();
            warp::reply::json(&serde_json::from_str::<serde_json::Value>(&response_body).unwrap())
        });

        // Start warp server
        let (addr, server) = warp::serve(mock_service)
            .bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            });

        let server_addr = addr;
        let _ = spawn(server);

        let client = Client::new();
        let base_url = format!("http://{}", server_addr);
        let tee_client = TeeHttpClient {
            base_url: base_url.clone(),
            client: client.clone(),
        };

        // Original encryption request
        let encryption_request = IoEncryptionRequest {
            msg_sender: PublicKey::from_str("03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd").unwrap(),
            data: plaintext.clone(),
            nonce: 12345678,
        };

        // Test encrypt
        let enc_response = tee_client.io_encrypt(encryption_request).await.unwrap();
        assert_eq!(enc_response.encrypted_data, ciphertext);

        // Original decryption request
        let decryption_request = IoDecryptionRequest {
            msg_sender: PublicKey::from_str("03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd").unwrap(),
            data: enc_response.encrypted_data,
            nonce: 12345678,
        };

        // Test decrypt
        let dec_response = tee_client.io_decrypt(decryption_request.clone()).await.unwrap();
        assert_eq!(dec_response.decrypted_data, plaintext);
    }
}
