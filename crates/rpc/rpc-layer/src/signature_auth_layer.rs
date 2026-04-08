use alloy_primitives::{address, Address, Signature, B256};
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use jsonrpsee_http_client::{HttpBody, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::{Layer, Service};

// EIP-712 typed data definition for ops requests.
sol! {
    #[derive(Debug)]
    struct OpsRequest {
        bytes body;
        string nonce;
    }

    interface OpsWhitelistTxAuth {
        function whitelistKey(address target, uint64 expiresAt) external;
        function revokeKey(address target) external;
    }
}

/// Header name for the hex-encoded secp256k1 signature.
pub const SIGNATURE_HEADER: &str = "X-Signature";

/// Header name for the nonce (replay protection).
pub const NONCE_HEADER: &str = "X-Nonce";

/// Sentinel address that ops governance transactions must target.
pub const WHITELIST_TX_SENTINEL: Address = address!("1000000000000000000000000000000000000006");

/// The Params contract address holding the authorized governance signer.
pub const OPS_AUTH_CONTRACT: Address = address!("0x0000000000000000000000000000506172616d73");

/// Storage slot 0 in the Params contract contains the admin address.
pub const OPS_AUTH_SLOT: B256 = B256::ZERO;

/// Shared whitelist of temporarily authorized addresses with expiration times.
#[derive(Debug, Clone)]
pub struct Whitelist {
    inner: Arc<RwLock<HashMap<Address, u64>>>,
}

impl Whitelist {
    /// Creates an empty whitelist.
    pub fn new() -> Self {
        Self { inner: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Adds an address to the whitelist until the given Unix timestamp in seconds.
    pub fn add(&self, address: Address, expires_at: u64) {
        write_unpoisoned(&self.inner).insert(address, expires_at);
    }

    /// Returns `true` if the address is whitelisted and not expired.
    pub fn is_authorized(&self, address: &Address) -> bool {
        let map = read_unpoisoned(&self.inner);
        match map.get(address) {
            Some(expiry) => current_unix_timestamp() < *expiry,
            None => false,
        }
    }

    /// Removes an address from the whitelist. Returns `true` if it was present.
    pub fn remove(&self, address: &Address) -> bool {
        write_unpoisoned(&self.inner).remove(address).is_some()
    }

    /// Removes expired entries.
    pub fn evict_expired(&self) {
        let now = current_unix_timestamp();
        write_unpoisoned(&self.inner).retain(|_, expiry| now < *expiry);
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self::new()
    }
}

/// The EIP-712 domain name for ops requests.
pub const EIP712_DOMAIN_NAME: &str = "SeismicOps";

/// The EIP-712 domain version for ops requests.
pub const EIP712_DOMAIN_VERSION: &str = "1";

/// Configuration for the signature authentication layer.
///
/// A shared whitelist holds temporarily authorized addresses for data endpoints.
/// Signatures use EIP-712 typed data with the `SeismicOps` domain.
#[derive(Debug, Clone)]
pub struct SignatureAuthConfig {
    /// Shared whitelist of temporarily authorized addresses.
    pub whitelist: Whitelist,
    /// In-memory next expected nonce per whitelisted signer.
    pub nonces: Arc<RwLock<HashMap<Address, u64>>>,
    /// The chain ID for the EIP-712 domain separator.
    pub chain_id: u64,
}

impl SignatureAuthConfig {
    /// Creates a new signature auth config.
    pub fn new(whitelist: Whitelist, chain_id: u64) -> Self {
        Self { whitelist, nonces: Arc::new(RwLock::new(HashMap::new())), chain_id }
    }
}

/// Compute the EIP-712 signing hash for an ops request.
pub fn eip712_signing_hash(body: &[u8], nonce: &str, chain_id: u64) -> B256 {
    let domain = eip712_domain! {
        name: EIP712_DOMAIN_NAME,
        version: EIP712_DOMAIN_VERSION,
        chain_id: chain_id,
    };

    let request = OpsRequest { body: body.to_vec().into(), nonce: nonce.to_string() };

    request.eip712_signing_hash(&domain)
}

/// Tower layer for ops authentication using EIP-712 request signatures.
///
/// `ops_getStorageAt` and `ops_getNonce` use `X-Signature`.
/// `ops_getStorageAt` also requires `X-Nonce`.
#[expect(missing_debug_implementations)]
pub struct SignatureAuthLayer {
    config: SignatureAuthConfig,
}

impl SignatureAuthLayer {
    /// Creates a new signature auth layer.
    pub const fn new(config: SignatureAuthConfig) -> Self {
        Self { config }
    }
}

impl<Svc> Layer<Svc> for SignatureAuthLayer {
    type Service = SignatureAuthService<Svc>;

    fn layer(&self, inner: Svc) -> Self::Service {
        SignatureAuthService { config: self.config.clone(), inner }
    }
}

/// Tower service that implements single-signature authentication.
///
/// See [`SignatureAuthLayer`] for details.
#[derive(Clone)]
#[expect(missing_debug_implementations)]
pub struct SignatureAuthService<Svc> {
    config: SignatureAuthConfig,
    inner: Svc,
}

impl<Svc> Service<HttpRequest> for SignatureAuthService<Svc>
where
    Svc: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    Svc::Future: Send + 'static,
    Svc::Error: Send,
{
    type Response = HttpResponse;
    type Error = Svc::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest) -> Self::Future {
        let mut inner = self.inner.clone();
        let config = self.config.clone();

        Box::pin(async move {
            // Collect the body.
            let (parts, body) = req.into_parts();
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "Failed to read request body",
                    ))
                }
            };

            // Parse the method name from the JSON body to avoid substring-matching
            // bypasses via Unicode escapes (e.g. \u006f for 'o').
            let method = serde_json::from_slice::<RpcRequest>(&body_bytes)
                .map(|r| r.method)
                .unwrap_or_default();

            let needs_nonce = method == "ops_getStorageAt";
            let is_get_nonce_method = method == "ops_getNonce";
            let nonce = if needs_nonce {
                match extract_header(&parts.headers, NONCE_HEADER) {
                    Some(n) => Some(n.to_string()),
                    None => {
                        return Ok(error_response(StatusCode::BAD_REQUEST, "Missing X-Nonce header"))
                    }
                }
            } else {
                None
            };

            // All remaining ops methods use EIP-712 signature auth.
            let sig_hex = match extract_header(&parts.headers, SIGNATURE_HEADER) {
                Some(s) => s.to_string(),
                None => {
                    return Ok(error_response(StatusCode::BAD_REQUEST, "Missing X-Signature header"))
                }
            };

            // Compute the EIP-712 signing hash.
            let signing_nonce = nonce.as_deref().unwrap_or("");
            let hash = eip712_signing_hash(&body_bytes, signing_nonce, config.chain_id);

            // Parse the signature.
            let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(&sig_hex);
            let sig_bytes = match alloy_primitives::hex::decode(sig_hex) {
                Ok(b) => b,
                Err(e) => {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid signature hex: {e}"),
                    ))
                }
            };

            let signature = match Signature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(e) => {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid signature: {e}"),
                    ))
                }
            };

            // Recover the signer address.
            let recovered_address =
                match alloy_consensus::crypto::secp256k1::recover_signer(&signature, hash) {
                    Ok(addr) => addr,
                    Err(_) => {
                        return Ok(error_response(
                            StatusCode::UNAUTHORIZED,
                            "Signature recovery failed",
                        ))
                    }
                };

            if is_get_nonce_method {
                config.whitelist.evict_expired();
                if !config.whitelist.is_authorized(&recovered_address) {
                    return Ok(error_response(StatusCode::UNAUTHORIZED, "Key not whitelisted"));
                }

                let requested_address = match requested_nonce_address(&body_bytes) {
                    Ok(address) => address,
                    Err(err) => return Ok(error_response(StatusCode::BAD_REQUEST, &err)),
                };

                if requested_address != recovered_address {
                    return Ok(error_response(
                        StatusCode::UNAUTHORIZED,
                        "Can only query your own nonce",
                    ));
                }
            } else if needs_nonce {
                // ops_getStorageAt: require whitelisted address.
                config.whitelist.evict_expired();
                if !config.whitelist.is_authorized(&recovered_address) {
                    return Ok(error_response(StatusCode::UNAUTHORIZED, "Key not whitelisted"));
                }
            } else {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "Unknown or unsupported ops method",
                ));
            }

            if needs_nonce {
                let nonce = nonce.expect("nonce is required when needs_nonce is true");
                let nonce_value = match nonce.parse::<u64>() {
                    Ok(value) => value,
                    Err(_) => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "Nonce must be a valid u64",
                        ))
                    }
                };

                let mut nonces = write_unpoisoned(&config.nonces);
                let expected = nonces.get(&recovered_address).copied().unwrap_or(0);
                if nonce_value != expected {
                    return Ok(error_response(
                        StatusCode::UNAUTHORIZED,
                        &format!("Invalid nonce: expected {expected}"),
                    ));
                }
                nonces.insert(recovered_address, expected + 1);
            }

            // Forward the request.
            let new_body = HttpBody::from(body_bytes.to_vec());
            let new_req = HttpRequest::from_parts(parts, new_body);
            inner.call(new_req).await
        })
    }
}

fn requested_nonce_address(body: &[u8]) -> Result<Address, String> {
    let request: RpcRequest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if request.method != "ops_getNonce" {
        return Err("Expected ops_getNonce request".to_string());
    }
    parse_address_param(request.params.first(), "address")
}

fn extract_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn error_response(status: StatusCode, message: &str) -> HttpResponse {
    Response::builder()
        .status(status)
        .body(HttpBody::new(message.to_string()))
        .expect("building error response should not fail")
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before unix epoch").as_secs()
}

fn read_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|err| err.into_inner())
}

fn write_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|err| err.into_inner())
}

#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    params: Vec<serde_json::Value>,
}

fn parse_address_param(value: Option<&serde_json::Value>, field: &str) -> Result<Address, String> {
    let value = value.ok_or_else(|| format!("Missing {field}"))?;
    let addr = value.as_str().ok_or_else(|| format!("Invalid {field}"))?;
    addr.parse::<Address>().map_err(|e| e.to_string())
}
