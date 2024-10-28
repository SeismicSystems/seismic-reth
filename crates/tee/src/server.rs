use anyhow::{anyhow, Result, Error};
use hyper::{body::to_bytes, Body, Request, Response, Server, StatusCode};
use routerify::{Middleware, RequestInfo, Router, RouterService, ext::RequestExt};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{Keypair, SecretKey};
use serde_json::json;
use std::{convert::Infallible, str::FromStr};
use std::net::SocketAddr;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use alloy_rlp::{Decodable, Encodable};
use once_cell::sync::Lazy;

use crate::types::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse};


pub fn build_server() -> Server<hyper::server::conn::AddrIncoming, RouterService<Body, Infallible>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));

    let router: Router<Body, Infallible> = Router::builder()
        .middleware(Middleware::pre(logger))
        .post("/tx_io_encrypt", tx_io_encrypt_handler)
        .post("/tx_io_decrypt", tx_io_decrypt_handler)
        .err_handler(error_handler)
        .build()
        .unwrap();

    let service = RouterService::new(router).unwrap();
    Server::bind(&addr).serve(service)
}

// A middleware which logs an http request.
async fn logger(req: Request<Body>) -> Result<Request<Body>, Infallible> {
    println!(
        "{} {} {}",
        req.remote_addr(),
        req.method(),
        req.uri().path()
    );
    Ok(req)
}

// Define an error handler function which will accept the `routerify::Error`
// and the request information and generates an appropriate response.
async fn error_handler(err: routerify::RouteError) -> Response<Body> {
    println!("\n\nError: {:?}\n\n", err);
    eprintln!("{}", err);
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {}", err)))
        .unwrap()
}

static AES_KEY: Lazy<Key<Aes256Gcm>> = Lazy::new(|| {
    let rng = OsRng::default();
    let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);
    return key;
});

pub async fn tx_io_decrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into IoDecryptionRequest
    let decryption_request: IoDecryptionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };
    // load key and decrypt data
    let decrypted_data = aes_decrypt(&AES_KEY, &decryption_request.data, decryption_request.nonce);

    let decrypted_data = match decrypted_data {
        Ok(data) => data,
        Err(e) => {
            return Ok(invalid_ciphertext_resp(e));
        }
    };

    let response_body = IoDecryptionResponse { decrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))}

pub async fn tx_io_encrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into IoEncryptionRequest
    let encryption_request: IoEncryptionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    let encrypted_data = aes_encrypt(&AES_KEY, &encryption_request.data, encryption_request.nonce);

    let response_body = IoEncryptionResponse { encrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

/// Returns 400 Bad Request
/// Meant to be used if there is an error while reading the request body
pub fn invalid_req_body_resp() -> Response<Body> {
    let error_response = json!({ "error": "Invalid request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(error_response))
        .unwrap()
}

// Returns 400 Bad Request
// Meant to be used if deserializing the body into a json fails
pub fn invalid_json_body_resp() -> Response<Body> {
    let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(error_response))
        .unwrap()
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


/// Converts a `u64` nonce to a `GenericArray<u8, N>`, where `N` is the size expected by AES-GCM.
///
/// This function takes a `u64` nonce and converts it into a generic byte array
/// with the appropriate size for AES-GCM encryption.
///
/// # Arguments
/// * `nonce` - A 64-bit unsigned integer representing the nonce.
///
/// # Returns
/// A `GenericArray<u8, N>` where `N` is the expected nonce size for AES-GCM encryption.
fn u64_to_generic_u8_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce_bytes = nonce.to_be_bytes().to_vec();
    let crypto_nonce_size = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();
    nonce_bytes.resize(crypto_nonce_size, 0); // pad to the expected size
    GenericArray::clone_from_slice(&nonce_bytes)
}

/// Encrypts plaintext using AES-256 GCM with the provided key and nonce.
///
/// This function uses AES-GCM to encrypt a serializable object (of type `Encodable`)
/// using the provided AES key and nonce. The object is first serialized to a `Vec<u8>`
/// and then encrypted.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for encryption.
/// * `plaintext` - The object to encrypt, which must implement the `Encodable` trait.
/// * `nonce` - A 64-bit unsigned integer used as the nonce for the encryption process.
///
/// # Returns
/// A `Vec<u8>` containing the encrypted ciphertext.
///
/// # Panics
/// This function will panic if the encryption fails.
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

/// Decrypts ciphertext using AES-256 GCM with the provided key and nonce.
///
/// This function uses AES-GCM to decrypt a ciphertext into an object that implements
/// the `Decodable` trait. The function expects the ciphertext to be a `Vec<u8>`, and
/// it will return the deserialized object if the decryption is successful.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for decryption.
/// * `ciphertext` - A slice of bytes (`&[u8]`) representing the encrypted data.
/// * `nonce` - A 64-bit unsigned integer used as the nonce for decryption.
///
/// # Returns
/// The decrypted object of type `T`, where `T` implements the `Decodable` trait.
///
/// # Panics
/// This function will panic if decryption or decoding fails.
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
