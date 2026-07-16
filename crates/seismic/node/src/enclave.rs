//! Tools to obtain purpose keys: from the seismic-enclave-server's RPC, or built
//! locally from the well-known keys when running without an enclave.
use std::{str::FromStr, time::Duration};

use jsonrpsee_http_client::{HttpClient, HttpClientBuilder};
use reth_node_core::args::EnclaveArgs;
use seismic_enclave::{
    api::TdxQuoteRpcClient as _, secp256k1, GetPurposeKeysResponse, SchnorrkelKeypair,
};
use tracing::{info, warn};

/// The well-known rng keypair as `schnorrkel::Keypair::to_bytes()`:
/// 64 bytes of expanded secret (key || nonce) followed by the 32-byte public key.
/// No schnorrkel cryptography is performed anywhere with it — the RNG precompile
/// uses only the 64 secret bytes as HKDF input key material; the schnorrkel type
/// survives solely because `GetPurposeKeysResponse` declares it.
const WELL_KNOWN_RNG_KEYPAIR: [u8; 96] = [
    108, 143, 208, 128, 94, 149, 36, 232, 240, 31, 238, 111, 54, 39, 246, 163, 231, 190, 237, 137,
    76, 19, 107, 188, 78, 133, 126, 183, 245, 50, 56, 8, 121, 108, 125, 215, 62, 231, 212, 112, 83,
    141, 75, 154, 109, 225, 74, 71, 155, 254, 199, 42, 79, 100, 86, 93, 155, 190, 165, 181, 199,
    249, 195, 114, 74, 169, 221, 253, 131, 199, 106, 69, 109, 34, 131, 64, 216, 213, 235, 57, 49,
    17, 132, 159, 68, 170, 254, 50, 94, 250, 185, 128, 121, 181, 217, 54,
];

/// The well-known purpose keys, used when `--enclave.mock-server` is set (dev nodes
/// and pre-TEE deployments, which run no enclave at all).
///
/// These are real keys with zero secrecy, not mocks: on pre-TEE networks every node
/// boots with `--enclave.mock-server`, so they are the consensus-visible network
/// keys — wallets encrypt to this `tx_io_pk`, sync decrypts history with `tx_io_sk`,
/// and `rng_keypair` seeds the RNG precompile.
// TODO: by mainnet launch, a pre-TEE mainnet must not run keys published on GitHub —
// needs a per-network keypair obfuscated or provisioned outside source control,
// while sanvil/dev networks stay on the well-known keys.
#[allow(clippy::expect_used)] // hardcoded constants; validity is exercised by tests
pub fn well_known_purpose_keys() -> GetPurposeKeysResponse {
    GetPurposeKeysResponse {
        tx_io_sk: secp256k1::SecretKey::from_str(
            "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
        )
        .expect("valid well-known tx_io secret key"),
        tx_io_pk: secp256k1::PublicKey::from_str(
            "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
        )
        .expect("valid well-known tx_io public key"),
        snapshot_key_bytes: [0u8; 32],
        rng_keypair: SchnorrkelKeypair::from_bytes(&WELL_KNOWN_RNG_KEYPAIR)
            .expect("valid well-known rng keypair"),
    }
}

/// Builds the enclave JSON-RPC client, binding each request to the configured `enclave_timeout`.
#[allow(clippy::expect_used)] // Intentional panic on startup failure - enclave is required
fn build_enclave_client(config: &EnclaveArgs) -> HttpClient {
    HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(config.enclave_timeout))
        .build(format!("http://{}:{}", config.enclave_server_addr, config.enclave_server_port))
        .expect("Failed to build enclave client")
}

/// Fetch purpose keys: built locally when `--enclave.mock-server` is set, otherwise
/// fetched from the enclave server over HTTP.
/// This must be called before building the node components.
/// Panics if purpose keys cannot be fetched from the enclave.
///
/// Total fetch attempts = `config.retries` + 1 (one initial attempt plus `retries`
/// re-attempts); the `while failures <= config.retries` loop encodes this directly.
#[allow(clippy::expect_used)] // Intentional panic on startup failure - enclave is required
#[allow(clippy::panic)] // Intentional panic on fetching keys failure - enclave keys are required
pub async fn boot_enclave_and_fetch_keys<T>(config: &T) -> GetPurposeKeysResponse
where
    T: AsRef<EnclaveArgs>,
{
    let config = config.as_ref();
    if config.mock_server {
        info!(target: "reth::cli", "Using built-in well-known purpose keys (no enclave)");
        return well_known_purpose_keys();
    }
    let enclave_client = build_enclave_client(config);

    // Fetch purpose keys from enclave - this must succeed or we panic
    info!(target: "reth::cli", "Fetching purpose keys from enclave");
    let mut failures = 0;
    while failures <= config.retries {
        match enclave_client.get_purpose_keys(0).await {
            Ok(purpose_keys) => {
                info!(target: "reth::cli", "Successfully fetched purpose keys from enclave");
                return purpose_keys;
            }
            Err(e) => {
                warn!(target: "reth::cli", "Failure to fetch purpose keys {}/{}: {}", failures, config.retries, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(config.retry_seconds.into()))
                    .await;
                failures += 1;
            }
        }
    }
    panic!("FATAL: Failed to fetch purpose keys from enclave on boot after {} failures", failures);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // Test code - expect on failure is acceptable

    use super::*;
    use std::time::Instant;
    use tokio::net::TcpListener;

    /// sanvil and not-yet-upgraded testnet nodes (whose HTTP mock arm serves keys
    /// built from `seismic_enclave`'s sample-key fns) must produce these exact
    /// keys: `rng_keypair` is a consensus input via the RNG precompile, so drift
    /// splits the chain, and divergence from sanvil breaks dev-tooling interop.
    /// The mixed-fleet half of this concern is temporary — it ends once every
    /// testnet node runs the local arm; the sanvil half holds for as long as dev
    /// networks share keys with anvil.
    #[test]
    fn well_known_purpose_keys_match_enclave_crate() {
        use seismic_enclave::{
            get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
            get_unsecure_sample_secp256k1_sk,
        };

        let ours = well_known_purpose_keys();
        assert_eq!(ours.tx_io_sk, get_unsecure_sample_secp256k1_sk());
        assert_eq!(ours.tx_io_pk, get_unsecure_sample_secp256k1_pk());
        assert_eq!(ours.snapshot_key_bytes, [0u8; 32]);
        assert_eq!(
            ours.rng_keypair.to_bytes(),
            get_unsecure_sample_schnorrkel_keypair().to_bytes()
        );
    }

    /// The hardcoded `tx_io_pk` must actually be `tx_io_sk`'s public key — wallets
    /// ECDH against the published key, the node decrypts with the secret one.
    #[test]
    fn well_known_tx_io_keypair_is_consistent() {
        let keys = well_known_purpose_keys();
        assert_eq!(keys.tx_io_pk, keys.tx_io_sk.public_key(&secp256k1::Secp256k1::new()));
    }

    /// A stalled enclave endpoint (accepts connections but never replies) must make the fetch
    /// error within the configured `enclave_timeout`, not hang on the underlying client default.
    #[tokio::test]
    async fn enclave_timeout_bounds_a_stalled_fetch() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            // The Vec exists only to keep the sockets alive; it is never read.
            #[allow(clippy::collection_is_never_read)]
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // keep the connection open without ever responding
            }
        });

        let config = EnclaveArgs {
            enclave_server_addr: addr.ip(),
            enclave_server_port: addr.port(),
            enclave_timeout: 1,
            ..Default::default()
        };
        let client = build_enclave_client(&config);

        let started = Instant::now();
        let result = client.get_purpose_keys(0).await;

        assert!(result.is_err(), "stalled fetch should error, not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "fetch should be bounded by enclave_timeout, took {:?}",
            started.elapsed()
        );
    }
}
