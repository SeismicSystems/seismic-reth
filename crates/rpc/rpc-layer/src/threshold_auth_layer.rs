use crate::signature_scheme::{SignatureScheme, NONCE_HEADER, SIGNATURE_HEADER};
use bytes::Bytes;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use jsonrpsee_http_client::{HttpBody, HttpRequest, HttpResponse};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tower::{Layer, Service};

/// Header name for the request ID that groups signatures from different signers.
pub const REQUEST_ID_HEADER: &str = "X-Request-Id";

/// Tracks the state of a pending threshold request.
#[derive(Debug)]
struct PendingRequest {
    /// Indices of the public keys that have signed so far.
    signer_indices: Vec<usize>,
    /// The request body (from the first signer — subsequent signers must match).
    body: Bytes,
    /// When this pending request was created.
    created_at: Instant,
}

/// Shared mutable state for tracking pending threshold requests.
#[derive(Debug)]
struct ThresholdState {
    /// Map from request ID to pending request state.
    pending: HashMap<String, PendingRequest>,
}

impl ThresholdState {
    fn new() -> Self {
        Self { pending: HashMap::new() }
    }

    /// Remove all pending requests older than `ttl`.
    fn evict_expired(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.pending.retain(|_, req| now.duration_since(req.created_at) < ttl);
    }
}

/// Tower layer for threshold signature authentication.
///
/// Requires K-of-N valid signatures before forwarding a request to the inner service.
/// Each signer sends a separate HTTP request with the same `X-Request-Id` header.
/// The first K-1 requests receive a status response indicating how many signatures have been
/// collected. The K-th request is forwarded to the inner service.
#[expect(missing_debug_implementations)]
pub struct ThresholdAuthLayer<S: SignatureScheme> {
    config: ThresholdConfig<S>,
}

impl<S: SignatureScheme> ThresholdAuthLayer<S> {
    /// Creates a new threshold auth layer.
    pub fn new(config: ThresholdConfig<S>) -> Self {
        Self { config }
    }
}

impl<Svc, S> Layer<Svc> for ThresholdAuthLayer<S>
where
    S: SignatureScheme,
{
    type Service = ThresholdAuthService<Svc, S>;

    fn layer(&self, inner: Svc) -> Self::Service {
        ThresholdAuthService {
            config: self.config.clone(),
            state: Arc::new(Mutex::new(ThresholdState::new())),
            inner,
        }
    }
}

/// Configuration for the threshold authentication layer.
///
/// The public key list is behind an `Arc<RwLock<>>` so it can be shared with the RPC handler
/// for runtime key management (add/remove signer keys).
#[derive(Clone, Debug)]
pub struct ThresholdConfig<S: SignatureScheme> {
    /// The set of N known public keys, shared and mutable at runtime.
    pub public_keys: Arc<RwLock<Vec<S::PublicKey>>>,
    /// The number of required signatures (K).
    pub threshold: usize,
    /// Time-to-live for pending request groups. Incomplete groups are discarded after this
    /// duration.
    pub ttl: Duration,
}

impl<S: SignatureScheme> ThresholdConfig<S> {
    /// Creates a new threshold config with the given keys, threshold, and TTL.
    pub fn new(public_keys: Vec<S::PublicKey>, threshold: usize, ttl: Duration) -> Self {
        Self { public_keys: Arc::new(RwLock::new(public_keys)), threshold, ttl }
    }

    /// Adds a public key to the allowed signers. Returns `false` if already present.
    pub fn add_key(&self, key: S::PublicKey) -> bool
    where
        S::PublicKey: PartialEq,
    {
        let mut keys = self.public_keys.write().expect("threshold keys lock poisoned");
        if keys.contains(&key) {
            return false;
        }
        keys.push(key);
        true
    }

    /// Removes a public key from the allowed signers. Returns `false` if not found.
    pub fn remove_key(&self, key: &S::PublicKey) -> bool
    where
        S::PublicKey: PartialEq,
    {
        let mut keys = self.public_keys.write().expect("threshold keys lock poisoned");
        let len_before = keys.len();
        keys.retain(|k| k != key);
        keys.len() < len_before
    }
}

/// Tower service that implements threshold signature authentication.
///
/// See [`ThresholdAuthLayer`] for details.
#[derive(Clone)]
#[expect(missing_debug_implementations)]
pub struct ThresholdAuthService<Svc, S: SignatureScheme> {
    config: ThresholdConfig<S>,
    state: Arc<Mutex<ThresholdState>>,
    inner: Svc,
}

impl<Svc, S> Service<HttpRequest> for ThresholdAuthService<Svc, S>
where
    Svc: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    Svc::Future: Send + 'static,
    Svc::Error: Send,
    S: SignatureScheme,
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
        let state = self.state.clone();

        Box::pin(async move {
            // Collect the body.
            let (parts, body) = req.into_parts();
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return Ok(error_response(StatusCode::BAD_REQUEST, "Failed to read request body")),
            };

            // Extract required headers.
            let request_id = match extract_header(&parts.headers, REQUEST_ID_HEADER) {
                Some(id) => id.to_string(),
                None => return Ok(error_response(StatusCode::BAD_REQUEST, "Missing X-Request-Id header")),
            };

            let sig_hex = match extract_header(&parts.headers, SIGNATURE_HEADER) {
                Some(s) => s.to_string(),
                None => return Ok(error_response(StatusCode::BAD_REQUEST, "Missing X-Signature header")),
            };

            let nonce = match extract_header(&parts.headers, NONCE_HEADER) {
                Some(n) => n.to_string(),
                None => return Ok(error_response(StatusCode::BAD_REQUEST, "Missing X-Nonce header")),
            };

            // Parse the signature.
            let signature = match S::parse_signature(&sig_hex) {
                Ok(sig) => sig,
                Err(e) => return Ok(error_response(StatusCode::UNAUTHORIZED, &e.to_string())),
            };

            // Construct the signed message: body || nonce.
            let mut message = Vec::with_capacity(body_bytes.len() + nonce.len());
            message.extend_from_slice(&body_bytes);
            message.extend_from_slice(nonce.as_bytes());

            // Find which public key signed this request.
            let signer_index = {
                let public_keys =
                    config.public_keys.read().expect("threshold keys lock poisoned");
                match find_signer::<S>(&public_keys, &message, &signature) {
                    Some(idx) => idx,
                    None => return Ok(error_response(StatusCode::UNAUTHORIZED, "Signature does not match any known public key")),
                }
            };

            // Update shared state.
            let should_forward = {
                let mut state = state.lock().expect("threshold state lock poisoned");

                // Evict expired pending requests.
                state.evict_expired(config.ttl);

                let pending = state.pending.entry(request_id.clone()).or_insert_with(|| {
                    PendingRequest {
                        signer_indices: Vec::new(),
                        body: body_bytes.clone(),
                        created_at: Instant::now(),
                    }
                });

                // Verify the body matches the first signer's body.
                if pending.body != body_bytes {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "Request body does not match previous signers for this request ID",
                    ));
                }

                // Check for duplicate signer.
                if pending.signer_indices.contains(&signer_index) {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "This public key has already signed this request",
                    ));
                }

                pending.signer_indices.push(signer_index);
                let count = pending.signer_indices.len();
                let threshold = config.threshold;

                if count >= threshold {
                    // Threshold met — remove from pending and forward.
                    state.pending.remove(&request_id);
                    true
                } else {
                    false
                }
            };

            if should_forward {
                // Reconstruct the request and forward to the inner service.
                let new_body = HttpBody::from(body_bytes.to_vec());
                let new_req = HttpRequest::from_parts(parts, new_body);
                inner.call(new_req).await
            } else {
                // Return status response indicating progress.
                let count = {
                    let state = state.lock().expect("threshold state lock poisoned");
                    state.pending.get(&request_id).map(|p| p.signer_indices.len()).unwrap_or(0)
                };
                let msg = format!(
                    "{} of {} signatures received",
                    count, config.threshold
                );
                Ok(Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(HttpBody::new(msg))
                    .expect("building status response should not fail"))
            }
        })
    }
}

/// Try to verify the signature against each known public key, returning the index of the matching
/// one.
fn find_signer<S: SignatureScheme>(
    public_keys: &[S::PublicKey],
    message: &[u8],
    signature: &S::Signature,
) -> Option<usize> {
    public_keys.iter().enumerate().find_map(|(i, pk)| {
        S::verify(pk, message, signature).ok().map(|_| i)
    })
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

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::signature_scheme::ed25519::Ed25519;
    use ed25519_dalek::{Signer, SigningKey};
    use jsonrpsee_http_client::HttpBody;
    use std::{convert::Infallible, future::ready, time::Duration};

    /// Sign `body || nonce` with the given signing key and return hex-encoded signature.
    fn sign(key: &SigningKey, body: &[u8], nonce: &str) -> String {
        let mut message = Vec::with_capacity(body.len() + nonce.len());
        message.extend_from_slice(body);
        message.extend_from_slice(nonce.as_bytes());
        let sig = key.sign(&message);
        sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Generate a random ed25519 signing key.
    fn gen_key() -> SigningKey {
        SigningKey::generate(&mut rand::thread_rng())
    }

    #[derive(Clone)]
    struct EchoService;

    impl Service<HttpRequest> for EchoService {
        type Response = HttpResponse;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: HttpRequest) -> Self::Future {
            let response = HttpResponse::builder()
                .status(StatusCode::OK)
                .body(HttpBody::from("executed"))
                .unwrap();
            ready(Ok(response))
        }
    }

    fn setup_service(
        keys: &[&SigningKey],
        threshold: usize,
    ) -> impl Service<HttpRequest, Response = HttpResponse, Error = Infallible> {
        let public_keys = keys.iter().map(|k| k.verifying_key()).collect();
        let config = ThresholdConfig::<Ed25519>::new(public_keys, threshold, Duration::from_secs(60));
        ThresholdAuthLayer::new(config).layer(EchoService)
    }

    fn make_request(request_id: &str, sig_hex: &str, nonce: &str, body: &str) -> HttpRequest {
        HttpRequest::builder()
            .header(REQUEST_ID_HEADER, request_id)
            .header(SIGNATURE_HEADER, sig_hex)
            .header(NONCE_HEADER, nonce)
            .body(HttpBody::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn threshold_met_forwards_request() {
        let key1 = gen_key();
        let key2 = gen_key();
        let key3 = gen_key();
        let mut service = setup_service(&[&key1, &key2, &key3], 2);
        let body = "test body";
        let nonce = "nonce1";

        // First signer.
        let sig1 = sign(&key1, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig1, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Second signer — threshold met.
        let sig2 = sign(&key2, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig2, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn duplicate_signer_rejected() {
        let key1 = gen_key();
        let key2 = gen_key();
        let key3 = gen_key();
        let mut service = setup_service(&[&key1, &key2, &key3], 2);
        let body = "test body";
        let nonce = "nonce1";

        let sig1 = sign(&key1, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig1, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Same signer again.
        let resp = service.call(make_request("req1", &sig1, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mismatched_body_rejected() {
        let key1 = gen_key();
        let key2 = gen_key();
        let mut service = setup_service(&[&key1, &key2], 2);
        let nonce = "nonce1";

        let sig1 = sign(&key1, b"body A", nonce);
        let resp = service.call(make_request("req1", &sig1, nonce, "body A")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Different body for same request ID.
        let sig2 = sign(&key2, b"body B", nonce);
        let resp = service.call(make_request("req1", &sig2, nonce, "body B")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_signer_rejected() {
        let key1 = gen_key();
        let key2 = gen_key();
        let unknown = gen_key();
        let mut service = setup_service(&[&key1, &key2], 2);
        let body = "test body";
        let nonce = "nonce1";

        let sig = sign(&unknown, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_requests_evicted() {
        let key1 = gen_key();
        let key2 = gen_key();
        let public_keys = vec![key1.verifying_key(), key2.verifying_key()];
        let config = ThresholdConfig::<Ed25519>::new(public_keys, 2, Duration::from_millis(1));
        let mut service = ThresholdAuthLayer::new(config).layer(EchoService);

        let body = "test body";
        let nonce = "nonce1";

        let sig1 = sign(&key1, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig1, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Wait for TTL to expire.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Second signer — but the pending request has expired, so this starts fresh.
        let sig2 = sign(&key2, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig2, nonce, body)).await.unwrap();
        // Only 1 of 2 — the first was evicted.
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn missing_headers_rejected() {
        let key1 = gen_key();
        let mut service = setup_service(&[&key1], 1);

        // Missing all custom headers.
        let req = HttpRequest::builder().body(HttpBody::from("body")).unwrap();
        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn single_signer_threshold() {
        let key1 = gen_key();
        let mut service = setup_service(&[&key1], 1);
        let body = "test body";
        let nonce = "nonce1";

        let sig = sign(&key1, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig, nonce, body)).await.unwrap();
        // K=1, so first valid signature forwards immediately.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn add_key_succeeds() {
        let key1 = gen_key();
        let key2 = gen_key();
        let config =
            ThresholdConfig::<Ed25519>::new(vec![key1.verifying_key()], 1, Duration::from_secs(60));
        assert!(config.add_key(key2.verifying_key()));
        let keys = config.public_keys.read().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn add_duplicate_key_returns_false() {
        let key1 = gen_key();
        let config =
            ThresholdConfig::<Ed25519>::new(vec![key1.verifying_key()], 1, Duration::from_secs(60));
        assert!(!config.add_key(key1.verifying_key()));
        let keys = config.public_keys.read().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn remove_key_succeeds() {
        let key1 = gen_key();
        let key2 = gen_key();
        let config = ThresholdConfig::<Ed25519>::new(
            vec![key1.verifying_key(), key2.verifying_key()],
            1,
            Duration::from_secs(60),
        );
        assert!(config.remove_key(&key1.verifying_key()));
        let keys = config.public_keys.read().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], key2.verifying_key());
    }

    #[test]
    fn remove_unknown_key_returns_false() {
        let key1 = gen_key();
        let unknown = gen_key();
        let config =
            ThresholdConfig::<Ed25519>::new(vec![key1.verifying_key()], 1, Duration::from_secs(60));
        assert!(!config.remove_key(&unknown.verifying_key()));
        let keys = config.public_keys.read().unwrap();
        assert_eq!(keys.len(), 1);
    }

    /// Simulates the flow: threshold must be met before the inner service (which would call
    /// add_key) is reached. After adding a key, subsequent requests recognize the new signer.
    #[tokio::test]
    async fn key_added_after_threshold_met_is_recognized() {
        let key1 = gen_key();
        let key2 = gen_key();
        let key3 = gen_key();
        let config = ThresholdConfig::<Ed25519>::new(
            vec![key1.verifying_key(), key2.verifying_key()],
            2,
            Duration::from_secs(60),
        );
        let mut service = ThresholdAuthLayer::new(config.clone()).layer(EchoService);
        let body = "add key3";
        let nonce = "nonce1";

        // key3 is unknown — rejected before threshold can even be considered.
        let sig3 = sign(&key3, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig3, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // key1 signs — 1 of 2.
        let sig1 = sign(&key1, body.as_bytes(), nonce);
        let resp = service.call(make_request("req2", &sig1, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // key2 signs — 2 of 2, threshold met. The inner service would handle add_key here.
        let sig2 = sign(&key2, body.as_bytes(), nonce);
        let resp = service.call(make_request("req2", &sig2, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Simulate what the RPC handler does after the request is forwarded.
        config.add_key(key3.verifying_key());

        // Now key3 is recognized and can participate in threshold signing.
        let body2 = "next request";
        let nonce2 = "nonce2";
        let sig3 = sign(&key3, body2.as_bytes(), nonce2);
        let resp = service.call(make_request("req3", &sig3, nonce2, body2)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED); // 1 of 2, valid signer now
    }

    /// Simulates the flow: threshold must be met before the inner service (which would call
    /// remove_key) is reached. After removing a key, subsequent requests reject that signer.
    #[tokio::test]
    async fn key_removed_after_threshold_met_is_rejected() {
        let key1 = gen_key();
        let key2 = gen_key();
        let config = ThresholdConfig::<Ed25519>::new(
            vec![key1.verifying_key(), key2.verifying_key()],
            2,
            Duration::from_secs(60),
        );
        let mut service = ThresholdAuthLayer::new(config.clone()).layer(EchoService);
        let body = "remove key2";
        let nonce = "nonce1";

        // Both signers needed to authorize removal.
        let sig1 = sign(&key1, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig1, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let sig2 = sign(&key2, body.as_bytes(), nonce);
        let resp = service.call(make_request("req1", &sig2, nonce, body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK); // threshold met, forwarded

        // Simulate what the RPC handler does after the request is forwarded.
        config.remove_key(&key2.verifying_key());

        // key2 is no longer recognized.
        let body2 = "next request";
        let nonce2 = "nonce2";
        let sig2 = sign(&key2, body2.as_bytes(), nonce2);
        let resp = service.call(make_request("req2", &sig2, nonce2, body2)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
