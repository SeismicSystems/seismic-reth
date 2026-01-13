//! Rate limiting middleware for Seismic RPC server.
//!
//! Provides per-IP rate limiting using token bucket algorithm via the `governor` crate.
//!
//! ## Architecture
//!
//! 1. `ClientIpExtractorLayer` - HTTP middleware that extracts client IP from nginx headers
//! 2. `SeismicRateLimiter` - RPC middleware that enforces per-IP rate limits
//!
//! The IP flows through request extensions:
//! HTTP layer → extensions → jsonrpsee → RPC middleware

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use http::{Request, Response};
use jsonrpsee::{
    server::middleware::rpc::RpcServiceT, types::Request as RpcRequest, MethodResponse,
};
use std::{
    future::Future,
    net::IpAddr,
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

// ============================================================================
// ClientIp - Stored in request extensions
// ============================================================================

/// Client IP address extracted from HTTP headers.
///
/// This is stored in request extensions by `ClientIpExtractorService`
/// and read by `SeismicRateLimitingService`.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

// ============================================================================
// HTTP Middleware - Extract IP from nginx headers
// ============================================================================

/// Tower layer that extracts client IP from HTTP headers.
///
/// This must be added to the HTTP middleware stack to make
/// the client IP available to the RPC rate limiter.
#[derive(Clone, Debug, Default)]
pub struct ClientIpExtractorLayer;

impl<S> Layer<S> for ClientIpExtractorLayer {
    type Service = ClientIpExtractorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientIpExtractorService { inner }
    }
}

/// Service that extracts client IP from nginx headers and stores in extensions.
#[derive(Clone, Debug)]
pub struct ClientIpExtractorService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ClientIpExtractorService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // Extract client IP from nginx headers
        let client_ip = extract_client_ip_from_headers(&req);

        // Store in extensions for the RPC layer to read
        req.extensions_mut().insert(ClientIp(client_ip));

        self.inner.call(req)
    }
}

/// Extract client IP from HTTP headers set by nginx.
///
/// Checks in order:
/// 1. X-Forwarded-For (first IP in chain)
/// 2. X-Real-IP
/// 3. Falls back to 0.0.0.0
fn extract_client_ip_from_headers<B>(req: &Request<B>) -> IpAddr {
    // Try X-Forwarded-For first (standard proxy header)
    // Format: "client, proxy1, proxy2" - we want the first one
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP (nginx specific)
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.trim().parse() {
                return ip;
            }
        }
    }

    // Fallback - this shouldn't happen if nginx is configured correctly
    // Using 0.0.0.0 makes it obvious something is wrong
    "0.0.0.0".parse().unwrap()
}

// ============================================================================
// Rate Limit Configuration
// ============================================================================

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second allowed per IP.
    pub requests_per_second: u32,

    /// Burst size - how many requests can come in at once before limiting.
    /// This allows short bursts while still enforcing the overall rate.
    pub burst_size: u32,

    /// Methods to rate limit. If empty, all methods are rate limited.
    /// Prefix matching is used, e.g., "eth_" matches all eth_ methods.
    pub limited_methods: Option<Vec<String>>,

    /// Methods to exempt from rate limiting.
    /// These are never rate limited regardless of `limited_methods`.
    pub exempt_methods: Vec<String>,

    /// IP addresses to exempt from rate limiting.
    /// Useful for internal services.
    pub exempt_ips: Vec<IpAddr>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 50,
            limited_methods: vec![], // empty = limit all methods
            exempt_methods: vec![
                "eth_chainId".to_string(),
                "eth_blockNumber".to_string(),
                "net_version".to_string(),
                "web3_clientVersion".to_string(),
            ],
            exempt_ips: vec![],
        }
    }
}

// ============================================================================
// RPC Middleware - Rate Limiting Service
// ============================================================================

/// Type alias for the per-IP rate limiter.
type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Seismic rate limiter using token bucket algorithm.
///
/// Tracks per-IP request rates and rejects requests that exceed the limit.
#[derive(Clone)]
pub struct SeismicRateLimiter {
    /// Per-IP rate limiters stored in a concurrent hashmap.
    ip_limiters: Arc<DashMap<IpAddr, Arc<IpRateLimiter>>>,
    /// Configuration.
    config: Arc<RateLimitConfig>,
    /// Quota used for creating new rate limiters.
    quota: Quota,
}

impl std::fmt::Debug for SeismicRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeismicRateLimiter")
            .field("config", &self.config)
            .field("active_ips", &self.ip_limiters.len())
            .finish()
    }
}

impl SeismicRateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let rps = NonZeroU32::new(config.requests_per_second).unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(config.burst_size).unwrap_or(NonZeroU32::MIN);

        let quota = Quota::per_second(rps).allow_burst(burst);

        Self { ip_limiters: Arc::new(DashMap::new()), config: Arc::new(config), quota }
    }

    /// Create a rate limiter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Get or create a rate limiter for the given IP.
    fn get_limiter(&self, ip: IpAddr) -> Arc<IpRateLimiter> {
        self.ip_limiters
            .entry(ip)
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota)))
            .clone()
    }

    /// Check if a method should be rate limited.
    fn should_limit_method(&self, method: &str) -> bool {
        // Check exempt methods first
        for exempt in &self.config.exempt_methods {
            if method == exempt || method.starts_with(exempt) {
                return false;
            }
        }

        // If no limited_methods specified, limit all (except exempt)
        if self.config.limited_methods.is_empty() {
            return true;
        }

        // Check if method matches any limited prefix
        for limited in &self.config.limited_methods {
            if method == limited || method.starts_with(limited) {
                return true;
            }
        }

        false
    }

    /// Check if an IP is exempt from rate limiting.
    fn is_ip_exempt(&self, ip: IpAddr) -> bool {
        self.config.exempt_ips.contains(&ip)
    }

    /// Check if a request should be allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err(())` if rate limited.
    pub fn check(&self, ip: IpAddr, method: &str) -> Result<(), ()> {
        // Check exemptions
        if self.is_ip_exempt(ip) || !self.should_limit_method(method) {
            return Ok(());
        }

        // Get or create limiter for this IP
        let limiter = self.get_limiter(ip);

        // Try to acquire a token
        limiter.check().map_err(|_| ())
    }

    /// Get the number of currently tracked IPs.
    /// Useful for monitoring.
    pub fn active_ip_count(&self) -> usize {
        self.ip_limiters.len()
    }

    /// Clear old entries from the limiter map.
    /// Call this periodically to prevent memory growth.
    pub fn cleanup_stale_entries(&self) {
        // For now, we don't have TTL tracking on entries.
        // In production, you might want to add timestamps and prune old entries.
        // The governor crate handles token refill automatically.
    }
}

// Implement Tower Layer for SeismicRateLimiter
impl<S> Layer<S> for SeismicRateLimiter {
    type Service = SeismicRateLimitingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SeismicRateLimitingService { inner, rate_limiter: self.clone() }
    }
}

/// RPC service that applies rate limiting.
#[derive(Clone, Debug)]
pub struct SeismicRateLimitingService<S> {
    inner: S,
    rate_limiter: SeismicRateLimiter,
}

impl<S> SeismicRateLimitingService<S> {
    /// Create a new rate limiting service.
    pub const fn new(inner: S, rate_limiter: SeismicRateLimiter) -> Self {
        Self { inner, rate_limiter }
    }
}

impl<S> RpcServiceT for SeismicRateLimitingService<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Send + Sync + Clone + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(
        &self,
        req: RpcRequest<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        // Extract client IP from extensions (set by HTTP middleware)
        let client_ip = req
            .extensions()
            .get::<ClientIp>()
            .map(|c| c.0)
            .unwrap_or_else(|| "0.0.0.0".parse().unwrap());

        let method_name = req.method_name();

        // Check rate limit
        if self.rate_limiter.check(client_ip, method_name).is_err() {
            // Rate limited - return error immediately
            let error = jsonrpsee::types::ErrorObject::owned(
                -32029, // Custom error code for rate limiting
                "Rate limited".to_string(),
                Some(format!("Too many requests from {}", client_ip)),
            );

            return futures::future::Either::Left(
                async move { MethodResponse::error(req.id(), error) },
            );
        }

        // Not rate limited - proceed with the request
        let fut = self.inner.call(req);
        futures::future::Either::Right(fut)
    }

    fn batch<'a>(
        &self,
        requests: jsonrpsee::core::middleware::Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        // For batch requests, we could rate limit the whole batch or each request
        // For simplicity, we pass through and let individual calls be limited
        self.inner.batch(requests)
    }

    fn notification<'a>(
        &self,
        n: jsonrpsee::core::middleware::Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // Notifications don't get responses, so no rate limiting
        self.inner.notification(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // RateLimitConfig Tests
    // ========================================================================

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_second, 100);
        assert_eq!(config.burst_size, 50);
        assert!(config.exempt_methods.contains(&"eth_chainId".to_string()));
        assert!(config.exempt_methods.contains(&"eth_blockNumber".to_string()));
        assert!(config.exempt_methods.contains(&"net_version".to_string()));
        assert!(config.exempt_methods.contains(&"web3_clientVersion".to_string()));
        assert!(config.limited_methods.is_empty());
        assert!(config.exempt_ips.is_empty());
    }

    #[test]
    fn test_rate_limit_config_custom() {
        let config = RateLimitConfig {
            requests_per_second: 50,
            burst_size: 10,
            limited_methods: vec!["eth_call".to_string()],
            exempt_methods: vec!["eth_chainId".to_string()],
            exempt_ips: vec!["127.0.0.1".parse().unwrap()],
        };
        assert_eq!(config.requests_per_second, 50);
        assert_eq!(config.burst_size, 10);
        assert_eq!(config.limited_methods.len(), 1);
        assert_eq!(config.exempt_methods.len(), 1);
        assert_eq!(config.exempt_ips.len(), 1);
    }

    // ========================================================================
    // IP Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_ip_from_x_forwarded_for_single() {
        let req = Request::builder().header("x-forwarded-for", "203.0.113.50").body(()).unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_from_x_forwarded_for_chain() {
        // When multiple proxies, first IP is the client
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.50, 70.41.3.18, 150.172.238.178")
            .body(())
            .unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_from_x_forwarded_for_with_spaces() {
        let req = Request::builder()
            .header("x-forwarded-for", "  203.0.113.50  ,  70.41.3.18  ")
            .body(())
            .unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_from_x_real_ip() {
        let req = Request::builder().header("x-real-ip", "192.168.1.100").body(()).unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "192.168.1.100".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_prefers_x_forwarded_for_over_x_real_ip() {
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.1")
            .header("x-real-ip", "10.0.0.2")
            .body(())
            .unwrap();
        let ip = extract_client_ip_from_headers(&req);
        // X-Forwarded-For takes priority
        assert_eq!(ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_fallback_when_no_headers() {
        let req = Request::builder().body(()).unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_fallback_when_invalid_header() {
        let req =
            Request::builder().header("x-forwarded-for", "not-an-ip-address").body(()).unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ipv6_address() {
        let req = Request::builder().header("x-forwarded-for", "2001:db8::1").body(()).unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_case_insensitive_header() {
        // HTTP headers are case-insensitive, but http crate normalizes them
        let req = Request::builder().header("X-Forwarded-For", "10.20.30.40").body(()).unwrap();
        let ip = extract_client_ip_from_headers(&req);
        assert_eq!(ip, "10.20.30.40".parse::<IpAddr>().unwrap());
    }

    // ========================================================================
    // Method Filtering Tests
    // ========================================================================

    #[test]
    fn test_should_limit_method_with_specific_methods() {
        let config = RateLimitConfig {
            limited_methods: vec!["eth_call".to_string(), "eth_send".to_string()],
            exempt_methods: vec!["eth_chainId".to_string()],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        // Exact matches
        assert!(limiter.should_limit_method("eth_call"));

        // Prefix matches
        assert!(limiter.should_limit_method("eth_sendRawTransaction"));
        assert!(limiter.should_limit_method("eth_sendTransaction"));

        // Exempt method
        assert!(!limiter.should_limit_method("eth_chainId"));

        // Not in limited_methods list
        assert!(!limiter.should_limit_method("eth_blockNumber"));
        assert!(!limiter.should_limit_method("eth_getBalance"));
        assert!(!limiter.should_limit_method("debug_traceTransaction"));
    }

    #[test]
    fn test_should_limit_method_empty_limited_methods_limits_all() {
        let config = RateLimitConfig {
            limited_methods: vec![], // empty = limit all
            exempt_methods: vec!["eth_chainId".to_string()],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        // All methods should be limited except exempt ones
        assert!(limiter.should_limit_method("eth_call"));
        assert!(limiter.should_limit_method("eth_sendRawTransaction"));
        assert!(limiter.should_limit_method("debug_traceTransaction"));
        assert!(limiter.should_limit_method("any_random_method"));

        // Exempt method should not be limited
        assert!(!limiter.should_limit_method("eth_chainId"));
    }

    #[test]
    fn test_should_limit_method_exempt_takes_priority() {
        let config = RateLimitConfig {
            limited_methods: vec!["eth_".to_string()], // All eth_ methods
            exempt_methods: vec!["eth_chainId".to_string(), "eth_blockNumber".to_string()],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        // Limited by prefix
        assert!(limiter.should_limit_method("eth_call"));
        assert!(limiter.should_limit_method("eth_getBalance"));

        // Exempt takes priority over limited
        assert!(!limiter.should_limit_method("eth_chainId"));
        assert!(!limiter.should_limit_method("eth_blockNumber"));
    }

    #[test]
    fn test_should_limit_method_prefix_matching() {
        let config = RateLimitConfig {
            limited_methods: vec!["debug_".to_string(), "trace_".to_string()],
            exempt_methods: vec![],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        assert!(limiter.should_limit_method("debug_traceTransaction"));
        assert!(limiter.should_limit_method("debug_storageRangeAt"));
        assert!(limiter.should_limit_method("trace_block"));
        assert!(limiter.should_limit_method("trace_call"));

        // Not matching prefixes
        assert!(!limiter.should_limit_method("eth_call"));
        assert!(!limiter.should_limit_method("net_version"));
    }

    // ========================================================================
    // IP Exemption Tests
    // ========================================================================

    #[test]
    fn test_exempt_ip_single() {
        let config = RateLimitConfig {
            exempt_ips: vec!["192.168.1.1".parse().unwrap()],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        assert!(limiter.is_ip_exempt("192.168.1.1".parse().unwrap()));
        assert!(!limiter.is_ip_exempt("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_exempt_ip_multiple() {
        let config = RateLimitConfig {
            exempt_ips: vec![
                "192.168.1.1".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        assert!(limiter.is_ip_exempt("192.168.1.1".parse().unwrap()));
        assert!(limiter.is_ip_exempt("10.0.0.1".parse().unwrap()));
        assert!(limiter.is_ip_exempt("127.0.0.1".parse().unwrap()));
        assert!(!limiter.is_ip_exempt("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_exempt_ip_ipv6() {
        let config = RateLimitConfig {
            exempt_ips: vec!["::1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            ..Default::default()
        };
        let limiter = SeismicRateLimiter::new(config);

        assert!(limiter.is_ip_exempt("::1".parse().unwrap()));
        assert!(limiter.is_ip_exempt("2001:db8::1".parse().unwrap()));
        assert!(!limiter.is_ip_exempt("2001:db8::2".parse().unwrap()));
    }

    // ========================================================================
    // Rate Limiting Behavior Tests
    // ========================================================================

    #[test]
    fn test_rate_limiting_basic() {
        let config = RateLimitConfig {
            requests_per_second: 2,
            burst_size: 2,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // First two requests should succeed (burst)
        assert!(limiter.check(ip, "eth_call").is_ok());
        assert!(limiter.check(ip, "eth_call").is_ok());

        // Third request should be rate limited
        assert!(limiter.check(ip, "eth_call").is_err());
    }

    #[test]
    fn test_rate_limiting_per_ip_isolation() {
        let config = RateLimitConfig {
            requests_per_second: 2,
            burst_size: 2,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1's quota
        assert!(limiter.check(ip1, "eth_call").is_ok());
        assert!(limiter.check(ip1, "eth_call").is_ok());
        assert!(limiter.check(ip1, "eth_call").is_err());

        // ip2 should still have its own quota
        assert!(limiter.check(ip2, "eth_call").is_ok());
        assert!(limiter.check(ip2, "eth_call").is_ok());
        assert!(limiter.check(ip2, "eth_call").is_err());
    }

    #[test]
    fn test_rate_limiting_exempt_ip_bypasses() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 1,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec!["192.168.1.1".parse().unwrap()],
        };
        let limiter = SeismicRateLimiter::new(config);
        let exempt_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let normal_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exempt IP should never be rate limited
        for _ in 0..100 {
            assert!(limiter.check(exempt_ip, "eth_call").is_ok());
        }

        // Normal IP should be rate limited
        assert!(limiter.check(normal_ip, "eth_call").is_ok());
        assert!(limiter.check(normal_ip, "eth_call").is_err());
    }

    #[test]
    fn test_rate_limiting_exempt_method_bypasses() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 1,
            limited_methods: vec![],
            exempt_methods: vec!["eth_chainId".to_string()],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exempt method should never be rate limited
        for _ in 0..100 {
            assert!(limiter.check(ip, "eth_chainId").is_ok());
        }

        // Non-exempt method should be rate limited
        assert!(limiter.check(ip, "eth_call").is_ok());
        assert!(limiter.check(ip, "eth_call").is_err());
    }

    #[test]
    fn test_rate_limiting_different_methods_share_quota() {
        let config = RateLimitConfig {
            requests_per_second: 2,
            burst_size: 2,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Different methods from same IP share the same quota
        assert!(limiter.check(ip, "eth_call").is_ok());
        assert!(limiter.check(ip, "eth_getBalance").is_ok());
        assert!(limiter.check(ip, "eth_sendRawTransaction").is_err());
    }

    #[test]
    fn test_rate_limiting_burst_allows_quick_requests() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 5,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // All 5 burst requests should succeed immediately
        for i in 0..5 {
            assert!(
                limiter.check(ip, "eth_call").is_ok(),
                "Request {} should succeed within burst",
                i
            );
        }

        // 6th request should fail (burst exhausted)
        assert!(limiter.check(ip, "eth_call").is_err());
    }

    // ========================================================================
    // Active IP Count Tests
    // ========================================================================

    #[test]
    fn test_active_ip_count() {
        let config = RateLimitConfig::default();
        let limiter = SeismicRateLimiter::new(config);

        assert_eq!(limiter.active_ip_count(), 0);

        // Make requests from different IPs
        limiter.check("10.0.0.1".parse().unwrap(), "eth_call").ok();
        assert_eq!(limiter.active_ip_count(), 1);

        limiter.check("10.0.0.2".parse().unwrap(), "eth_call").ok();
        assert_eq!(limiter.active_ip_count(), 2);

        limiter.check("10.0.0.3".parse().unwrap(), "eth_call").ok();
        assert_eq!(limiter.active_ip_count(), 3);

        // Same IP shouldn't increase count
        limiter.check("10.0.0.1".parse().unwrap(), "eth_call").ok();
        assert_eq!(limiter.active_ip_count(), 3);
    }

    // ========================================================================
    // Constructor Tests
    // ========================================================================

    #[test]
    fn test_with_defaults() {
        let limiter = SeismicRateLimiter::with_defaults();
        // Should be able to make many requests with default config (100 rps, 50 burst)
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..50 {
            assert!(limiter.check(ip, "eth_call").is_ok());
        }
    }

    #[test]
    fn test_zero_values_use_minimum() {
        // Governor doesn't allow 0 for NonZeroU32, so we clamp to MIN
        let config =
            RateLimitConfig { requests_per_second: 0, burst_size: 0, ..Default::default() };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Should still work with minimum values (1 req/sec, 1 burst)
        assert!(limiter.check(ip, "eth_call").is_ok());
        assert!(limiter.check(ip, "eth_call").is_err());
    }

    // ========================================================================
    // ClientIp Type Tests
    // ========================================================================

    #[test]
    fn test_client_ip_clone_copy() {
        let ip1 = ClientIp("10.0.0.1".parse().unwrap());
        let ip2 = ip1; // Copy
        let ip3 = ip1.clone(); // Clone

        assert_eq!(ip1.0, ip2.0);
        assert_eq!(ip1.0, ip3.0);
    }

    #[test]
    fn test_client_ip_debug() {
        let ip = ClientIp("192.168.1.1".parse().unwrap());
        let debug_str = format!("{:?}", ip);
        assert!(debug_str.contains("192.168.1.1"));
    }

    // ========================================================================
    // Layer Implementation Tests
    // ========================================================================

    #[test]
    fn test_client_ip_extractor_layer_default() {
        let layer = ClientIpExtractorLayer::default();
        let _layer2 = layer.clone();
        let debug_str = format!("{:?}", layer);
        assert!(debug_str.contains("ClientIpExtractorLayer"));
    }

    #[test]
    fn test_seismic_rate_limiter_debug() {
        let limiter = SeismicRateLimiter::with_defaults();
        let debug_str = format!("{:?}", limiter);
        assert!(debug_str.contains("SeismicRateLimiter"));
        assert!(debug_str.contains("active_ips"));
    }

    #[test]
    fn test_seismic_rate_limiter_clone() {
        let limiter1 = SeismicRateLimiter::with_defaults();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Use some quota
        limiter1.check(ip, "eth_call").ok();

        // Clone should share the same internal state
        let limiter2 = limiter1.clone();
        assert_eq!(limiter1.active_ip_count(), limiter2.active_ip_count());
    }

    // ========================================================================
    // Token Refill Tests (Async)
    // ========================================================================

    #[tokio::test]
    async fn test_rate_limiting_tokens_refill_over_time() {
        let config = RateLimitConfig {
            requests_per_second: 10, // 10 per second = 1 token every 100ms
            burst_size: 1,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Use up the burst
        assert!(limiter.check(ip, "eth_call").is_ok());
        assert!(limiter.check(ip, "eth_call").is_err());

        // Wait for token to refill (slightly more than 100ms to be safe)
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

        // Should be able to make another request
        assert!(limiter.check(ip, "eth_call").is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiting_sustained_rate() {
        let config = RateLimitConfig {
            requests_per_second: 20, // 20 per second = 1 token every 50ms
            burst_size: 1,
            limited_methods: vec![],
            exempt_methods: vec![],
            exempt_ips: vec![],
        };
        let limiter = SeismicRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Make requests at a sustainable rate
        for _ in 0..5 {
            assert!(limiter.check(ip, "eth_call").is_ok());
            tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;
        }
    }

    // ========================================================================
    // Integration-like Tests
    // ========================================================================

    #[test]
    fn test_full_check_flow() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 5,
            limited_methods: vec!["eth_call".to_string(), "eth_send".to_string()],
            exempt_methods: vec!["eth_chainId".to_string()],
            exempt_ips: vec!["127.0.0.1".parse().unwrap()],
        };
        let limiter = SeismicRateLimiter::new(config);

        let normal_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let exempt_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Exempt IP can make unlimited requests to limited methods
        for _ in 0..100 {
            assert!(limiter.check(exempt_ip, "eth_call").is_ok());
        }

        // Normal IP can make unlimited requests to exempt methods
        for _ in 0..100 {
            assert!(limiter.check(normal_ip, "eth_chainId").is_ok());
        }

        // Normal IP can make unlimited requests to non-limited methods
        for _ in 0..100 {
            assert!(limiter.check(normal_ip, "net_version").is_ok());
        }

        // Normal IP is rate limited on limited methods
        for _ in 0..5 {
            assert!(limiter.check(normal_ip, "eth_call").is_ok());
        }
        assert!(limiter.check(normal_ip, "eth_call").is_err());
    }

    #[test]
    fn test_concurrent_access_safety() {
        use std::sync::Arc;
        use std::thread;

        let config =
            RateLimitConfig { requests_per_second: 1000, burst_size: 100, ..Default::default() };
        let limiter = Arc::new(SeismicRateLimiter::new(config));

        let mut handles = vec![];

        // Spawn multiple threads making requests
        for i in 0..10 {
            let limiter = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
                for _ in 0..50 {
                    let _ = limiter.check(ip, "eth_call");
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 10 unique IPs tracked
        assert_eq!(limiter.active_ip_count(), 10);
    }
}
