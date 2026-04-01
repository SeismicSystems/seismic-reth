use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::Decodable2718;
use alloy_primitives::{address, Address, Signature, B256};
use alloy_sol_types::{eip712_domain, sol, SolCall, SolStruct};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use jsonrpsee_http_client::{HttpBody, HttpRequest, HttpResponse};
use reth_storage_api::StateProviderFactory;
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

/// Header name for a raw signed Ethereum transaction used to authorize governance whitelist
/// requests.
pub const SIGNED_TX_HEADER: &str = "X-Signed-Tx";

/// Sentinel address that `ops_whitelistKey` governance auth transactions must target.
pub const WHITELIST_TX_SENTINEL: Address = address!("1000000000000000000000000000000000000006");

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
/// The governance address is read from a contract storage slot. A shared whitelist holds
/// temporarily authorized addresses for data endpoints.
/// Signatures use EIP-712 typed data with the SeismicOps domain.
#[derive(Debug)]
pub struct SignatureAuthConfig<P> {
    /// The state provider for reading contract storage.
    pub provider: Arc<P>,
    /// The contract address holding the governance address.
    pub contract_address: Address,
    /// The storage slot containing the governance address.
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

/// Tower layer for ops authentication using a mix of EIP-712 request signatures and signed
/// Ethereum transactions.
///
/// `ops_getStorageAt` and `ops_getNonce` continue to use `X-Signature`.
/// `ops_getStorageAt` also requires `X-Nonce`.
/// `ops_whitelistKey` and `ops_revokeKey` instead require `X-Signed-Tx`, containing a raw signed
/// transaction whose sender must be the configured governance address and whose calldata must
/// match the RPC params.
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

            // Parse the method name from the JSON body to avoid substring-matching
            // bypasses via Unicode escapes (e.g. \u006f for 'o').
            let method = serde_json::from_slice::<RpcRequest>(&body_bytes)
                .map(|r| r.method)
                .unwrap_or_default();

            let needs_nonce = method == "ops_getStorageAt";
            let is_governance_tx_method = method == "ops_whitelistKey" || method == "ops_revokeKey";
            let is_get_nonce_method = method == "ops_getNonce";
            let is_whitelist_method = method == "ops_whitelistKey";
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

            let recovered_address = if is_governance_tx_method {
                let signed_tx_hex = match extract_header(&parts.headers, SIGNED_TX_HEADER) {
                    Some(s) => s,
                    None => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "Missing X-Signed-Tx header",
                        ))
                    }
                };

                let governance_address = match read_authorized_address(
                    &config.provider,
                    config.contract_address,
                    config.storage_slot,
                ) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok(error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Failed to read governance address from contract: {e}"),
                        ))
                    }
                };

                match validate_governance_tx(
                    signed_tx_hex,
                    &body_bytes,
                    governance_address,
                    config.chain_id,
                    is_whitelist_method,
                ) {
                    Ok(addr) => addr,
                    Err(err) => return Ok(error_response(err.0, &err.1)),
                }
            } else {
                let sig_hex = match extract_header(&parts.headers, SIGNATURE_HEADER) {
                    Some(s) => s.to_string(),
                    None => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "Missing X-Signature header",
                        ))
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
                match alloy_consensus::crypto::secp256k1::recover_signer(&signature, hash) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok(error_response(
                            StatusCode::UNAUTHORIZED,
                            &format!("Signature recovery failed: {e}"),
                        ))
                    }
                }
            };

            if is_governance_tx_method {
                // Governance tx methods are fully authenticated by the signed transaction above.
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

fn requested_nonce_address(body: &[u8]) -> Result<Address, String> {
    match parse_ops_request(body)? {
        ParsedOpsRequest::GetNonce { address } => Ok(address),
        _ => Err("Expected ops_getNonce request".to_string()),
    }
}

fn requested_whitelist_params(body: &[u8]) -> Result<(Address, u64), String> {
    match parse_ops_request(body)? {
        ParsedOpsRequest::WhitelistKey { target, expires_at } => Ok((target, expires_at)),
        _ => Err("Expected ops_whitelistKey request".to_string()),
    }
}

fn requested_revoke_address(body: &[u8]) -> Result<Address, String> {
    match parse_ops_request(body)? {
        ParsedOpsRequest::RevokeKey { target } => Ok(target),
        _ => Err("Expected ops_revokeKey request".to_string()),
    }
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

enum ParsedOpsRequest {
    GetNonce { address: Address },
    WhitelistKey { target: Address, expires_at: u64 },
    RevokeKey { target: Address },
}

fn parse_ops_request(body: &[u8]) -> Result<ParsedOpsRequest, String> {
    let request: RpcRequest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    match request.method.as_str() {
        "ops_getNonce" => {
            let address = parse_address_param(request.params.first(), "address")?;
            Ok(ParsedOpsRequest::GetNonce { address })
        }
        "ops_whitelistKey" => {
            let target = parse_address_param(request.params.first(), "address")?;
            let expires_at = parse_u64_param(request.params.get(1), "expiry timestamp")?;
            Ok(ParsedOpsRequest::WhitelistKey { target, expires_at })
        }
        "ops_revokeKey" => {
            let target = parse_address_param(request.params.first(), "address")?;
            Ok(ParsedOpsRequest::RevokeKey { target })
        }
        method => Err(format!("Unexpected method: {method}")),
    }
}

fn parse_address_param(value: Option<&serde_json::Value>, field: &str) -> Result<Address, String> {
    let value = value.ok_or_else(|| format!("Missing {field}"))?;
    let addr = value.as_str().ok_or_else(|| format!("Invalid {field}"))?;
    addr.parse::<Address>().map_err(|e| e.to_string())
}

fn parse_u64_param(value: Option<&serde_json::Value>, field: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("Missing {field}"))?;
    value.as_u64().ok_or_else(|| format!("Invalid {field}"))
}

fn validate_governance_tx(
    signed_tx_hex: &str,
    body: &[u8],
    governance_address: Address,
    expected_chain_id: u64,
    is_whitelist: bool,
) -> Result<Address, (StatusCode, String)> {
    let tx_hex = signed_tx_hex.strip_prefix("0x").unwrap_or(signed_tx_hex);
    let tx_bytes = alloy_primitives::hex::decode(tx_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid signed tx hex: {e}")))?;
    let tx = TxEnvelope::decode_2718(&mut tx_bytes.as_slice())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid signed tx: {e}")))?;

    let recovered = tx.recover_signer().map_err(|e| {
        (StatusCode::UNAUTHORIZED, format!("Transaction signer recovery failed: {e}"))
    })?;
    if recovered != governance_address {
        return Err((StatusCode::UNAUTHORIZED, "Governance key required".to_string()));
    }

    if tx.chain_id() != Some(expected_chain_id) {
        return Err((StatusCode::UNAUTHORIZED, "Signed transaction chain ID mismatch".to_string()));
    }

    if tx.to() != Some(WHITELIST_TX_SENTINEL) {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("Signed transaction must target {WHITELIST_TX_SENTINEL}"),
        ));
    }

    if !tx.value().is_zero() {
        return Err((StatusCode::UNAUTHORIZED, "Signed transaction value must be 0".to_string()));
    }

    if is_whitelist {
        let call = OpsWhitelistTxAuth::whitelistKeyCall::abi_decode(tx.input()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Signed transaction calldata is not whitelistKey(address,uint64): {e}"),
            )
        })?;

        let (requested_target, requested_expires_at) =
            requested_whitelist_params(body).map_err(|e| {
                (StatusCode::BAD_REQUEST, format!("Invalid whitelist request params: {e}"))
            })?;

        if call.target != requested_target || call.expiresAt != requested_expires_at {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Signed transaction calldata does not match RPC params".to_string(),
            ));
        }

        if requested_expires_at <= current_unix_timestamp() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Expiry timestamp must be in the future".to_string(),
            ));
        }
    } else {
        let call = OpsWhitelistTxAuth::revokeKeyCall::abi_decode(tx.input()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Signed transaction calldata is not revokeKey(address): {e}"),
            )
        })?;
        let requested_target = requested_revoke_address(body).map_err(|e| {
            (StatusCode::BAD_REQUEST, format!("Invalid revoke request params: {e}"))
        })?;
        if call.target != requested_target {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Signed transaction calldata does not match RPC params".to_string(),
            ));
        }
    }

    Ok(recovered)
}
