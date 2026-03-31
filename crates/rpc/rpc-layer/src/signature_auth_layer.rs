use alloy_primitives::{Address, B256, Signature};
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use jsonrpsee_http_client::{HttpBody, HttpRequest, HttpResponse};
use reth_storage_api::StateProviderFactory;
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
}

/// Header name for the hex-encoded secp256k1 signature.
pub const SIGNATURE_HEADER: &str = "X-Signature";

/// Header name for the nonce (replay protection).
pub const NONCE_HEADER: &str = "X-Nonce";

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
        self.inner.write().expect("whitelist lock poisoned").insert(address, expires_at);
    }

    /// Returns `true` if the address is whitelisted and not expired.
    pub fn is_authorized(&self, address: &Address) -> bool {
        let map = self.inner.read().expect("whitelist lock poisoned");
        match map.get(address) {
            Some(expiry) => current_unix_timestamp() < *expiry,
            None => false,
        }
    }

    /// Removes an address from the whitelist. Returns `true` if it was present.
    pub fn remove(&self, address: &Address) -> bool {
        self.inner.write().expect("whitelist lock poisoned").remove(address).is_some()
    }

    /// Removes expired entries.
    pub fn evict_expired(&self) {
        let now = current_unix_timestamp();
        self.inner.write().expect("whitelist lock poisoned").retain(|_, expiry| now < *expiry);
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
/// The admin address is read from a contract storage slot. A shared whitelist holds
/// temporarily authorized addresses for data endpoints.
/// Signatures use EIP-712 typed data with the SeismicOps domain.
#[derive(Debug)]
pub struct SignatureAuthConfig<P> {
    /// The state provider for reading contract storage.
    pub provider: Arc<P>,
    /// The contract address holding the admin address.
    pub contract_address: Address,
    /// The storage slot containing the admin address.
    pub storage_slot: B256,
    /// Shared whitelist of temporarily authorized addresses.
    pub whitelist: Whitelist,
    /// In-memory next expected nonce per whitelisted signer.
    pub nonces: Arc<RwLock<HashMap<Address, u64>>>,
    /// The chain ID for the EIP-712 domain separator.
    pub chain_id: u64,
}

impl<P> Clone for SignatureAuthConfig<P> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            contract_address: self.contract_address,
            storage_slot: self.storage_slot,
            whitelist: self.whitelist.clone(),
            nonces: self.nonces.clone(),
            chain_id: self.chain_id,
        }
    }
}

impl<P> SignatureAuthConfig<P> {
    /// Creates a new signature auth config.
    pub fn new(
        provider: Arc<P>,
        contract_address: Address,
        storage_slot: B256,
        whitelist: Whitelist,
        chain_id: u64,
    ) -> Self {
        Self {
            provider,
            contract_address,
            storage_slot,
            whitelist,
            nonces: Arc::new(RwLock::new(HashMap::new())),
            chain_id,
        }
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

/// Tower layer for single-signature authentication using secp256k1 / Ethereum addresses.
///
/// Each request must include `X-Signature` and `X-Nonce` headers. The middleware:
/// 1. Hashes `keccak256(body || nonce)`
/// 2. Recovers the signer address from the signature
/// 3. Reads the authorized address from a contract storage slot
/// 4. Forwards the request if the addresses match
#[expect(missing_debug_implementations)]
pub struct SignatureAuthLayer<P> {
    config: SignatureAuthConfig<P>,
}

impl<P> SignatureAuthLayer<P> {
    /// Creates a new signature auth layer.
    pub fn new(config: SignatureAuthConfig<P>) -> Self {
        Self { config }
    }
}

impl<Svc, P> Layer<Svc> for SignatureAuthLayer<P>
where
    P: Send + Sync + 'static,
{
    type Service = SignatureAuthService<Svc, P>;

    fn layer(&self, inner: Svc) -> Self::Service {
        SignatureAuthService { config: self.config.clone(), inner }
    }
}

/// Tower service that implements single-signature authentication.
///
/// See [`SignatureAuthLayer`] for details.
#[expect(missing_debug_implementations)]
pub struct SignatureAuthService<Svc, P> {
    config: SignatureAuthConfig<P>,
    inner: Svc,
}

impl<Svc: Clone, P> Clone for SignatureAuthService<Svc, P> {
    fn clone(&self) -> Self {
        Self { config: self.config.clone(), inner: self.inner.clone() }
    }
}

impl<Svc, P> Service<HttpRequest> for SignatureAuthService<Svc, P>
where
    Svc: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    Svc::Future: Send + 'static,
    Svc::Error: Send,
    P: StateProviderFactory + 'static,
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

            // Extract required headers.
            let sig_hex = match extract_header(&parts.headers, SIGNATURE_HEADER) {
                Some(s) => s.to_string(),
                None => {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "Missing X-Signature header",
                    ))
                }
            };

            let needs_nonce = requires_nonce(&body_bytes);
            let nonce = if needs_nonce {
                match extract_header(&parts.headers, NONCE_HEADER) {
                    Some(n) => Some(n.to_string()),
                    None => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "Missing X-Nonce header",
                        ))
                    }
                }
            } else {
                None
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
                    Err(e) => {
                        return Ok(error_response(
                            StatusCode::UNAUTHORIZED,
                            &format!("Signature recovery failed: {e}"),
                        ))
                    }
                };

            // Determine which auth check to apply based on the JSON-RPC method name.
            let is_admin_method = is_admin_only_method(&body_bytes);
            let is_get_nonce_method = is_get_nonce_method(&body_bytes);

            if is_admin_method {
                // Admin-only methods (e.g. ops_whitelistKey): require admin address from contract.
                let admin_address = match read_authorized_address(
                    &config.provider,
                    config.contract_address,
                    config.storage_slot,
                ) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok(error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Failed to read admin address from contract: {e}"),
                        ))
                    }
                };

                if recovered_address != admin_address {
                    return Ok(error_response(StatusCode::UNAUTHORIZED, "Admin key required"));
                }
            } else if is_get_nonce_method {
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
            } else {
                // Data methods (e.g. ops_getStorageAt): require whitelisted address.
                config.whitelist.evict_expired();
                if !config.whitelist.is_authorized(&recovered_address) {
                    return Ok(error_response(StatusCode::UNAUTHORIZED, "Key not whitelisted"));
                }
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

                let mut nonces = config.nonces.write().expect("nonce lock poisoned");
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

/// Read an Ethereum address from a contract storage slot.
fn read_authorized_address<P: StateProviderFactory>(
    provider: &P,
    contract_address: Address,
    storage_slot: B256,
) -> Result<Address, String> {
    let state = provider.latest().map_err(|e| e.to_string())?;
    let value = state.storage(contract_address, storage_slot).map_err(|e| e.to_string())?;
    let storage_value = value.unwrap_or_default();
    // Address is stored in the lower 20 bytes of the 32-byte storage slot.
    let bytes = storage_value.value.to_be_bytes::<32>();
    Ok(Address::from_slice(&bytes[12..]))
}

/// Check if the JSON-RPC method in the body is an admin-only method.
/// Admin methods require the admin key from the contract storage.
/// All other methods require a whitelisted key.
fn is_admin_only_method(body: &[u8]) -> bool {
    // Quick check: look for the method name in the JSON body without full parsing.
    // This is safe because we only need to distinguish between known method names.
    let body_str = std::str::from_utf8(body).unwrap_or("");
    body_str.contains("\"ops_whitelistKey\"") || body_str.contains("\"ops_revokeKey\"")
}

fn is_get_nonce_method(body: &[u8]) -> bool {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    body_str.contains("\"ops_getNonce\"")
}

fn requires_nonce(body: &[u8]) -> bool {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    body_str.contains("\"ops_getStorageAt\"")
}

fn requested_nonce_address(body: &[u8]) -> Result<Address, String> {
    let body_str = std::str::from_utf8(body).map_err(|e| e.to_string())?;
    let params_idx = body_str.find("\"params\"").ok_or_else(|| "Missing params".to_string())?;
    let params_str = &body_str[params_idx..];
    let start = params_str.find('[').ok_or_else(|| "Invalid params".to_string())?;
    let after_bracket = &params_str[start + 1..];
    let first_quote = after_bracket.find('"').ok_or_else(|| "Missing address".to_string())?;
    let rest = &after_bracket[first_quote + 1..];
    let end_quote = rest.find('"').ok_or_else(|| "Invalid address".to_string())?;
    let addr_str = &rest[..end_quote];
    addr_str.parse::<Address>().map_err(|e| e.to_string())
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
