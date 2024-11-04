//! This module provides functionality for encryption and decryption
//! using a Trusted Execution Environment (TEE) client.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
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
use tokio::task;

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
        println!("Base URL: {}", base_url);
        Self { base_url, client: Client::new() }
    }

    /// Creates a new instance of the TEE client
    pub fn new_from_addr_port(addr: IpAddr, port: u16) -> Self {
        Self { base_url: format!("http://{}:{}", addr, port), client: Client::new() }
    }

    pub fn new_from_addr(addr: &SocketAddr) -> Self {
        let base_url = format!("http://{}", addr);
        println!("Base URL: {}", base_url);
        Self { base_url, client: Client::new() }
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
    .map_err(|_| TeeError::DecryptionError)?;
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
