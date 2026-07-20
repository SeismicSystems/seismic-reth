//! Tools to obtain purpose keys: from the local key custodian's Unix socket, or built
//! locally from the well-known keys when running without a TEE.
use std::{path::Path, str::FromStr, time::Duration};

use alloy_seismic_evm::{secp256k1, PurposeKeys};
use reth_node_core::args::EnclaveArgs;
use seismic_custodian_ipc::{CustodianClient, RngIkmBytes, TxIoKeypairBytes};
use tracing::{info, warn};

/// The key epoch this node fetches its purpose keys at. Epochs only advance on an
/// explicit operator-triggered rotation (a consensus event); until that mechanism
/// exists every node derives at epoch 0.
const PURPOSE_KEY_EPOCH: u64 = 0;

/// The well-known rng HKDF input key material, as `schnorrkel::SecretKey::to_bytes()`
/// (32-byte key || 32-byte nonce) of the well-known keypair. No schnorrkel
/// cryptography is performed anywhere with it — the RNG precompile consumes it as
/// HKDF ikm only.
const WELL_KNOWN_RNG_IKM: [u8; 64] = [
    108, 143, 208, 128, 94, 149, 36, 232, 240, 31, 238, 111, 54, 39, 246, 163, 231, 190, 237, 137,
    76, 19, 107, 188, 78, 133, 126, 183, 245, 50, 56, 8, 121, 108, 125, 215, 62, 231, 212, 112, 83,
    141, 75, 154, 109, 225, 74, 71, 155, 254, 199, 42, 79, 100, 86, 93, 155, 190, 165, 181, 199,
    249, 195, 114,
];

/// The well-known purpose keys, used when `--enclave.mock-server` is set (dev nodes
/// and pre-TEE deployments, which run no TEE at all).
///
/// These are real keys with zero secrecy, not mocks: on pre-TEE networks every node
/// boots with `--enclave.mock-server`, so they are the consensus-visible network
/// keys — wallets encrypt to this `tx_io_pk`, sync decrypts history with `tx_io_sk`,
/// and `rng_ikm` seeds the RNG precompile.
// TODO: by mainnet launch, a pre-TEE mainnet must not run keys published on GitHub —
// needs a per-network keypair obfuscated or provisioned outside source control,
// while sanvil/dev networks stay on the well-known keys.
#[allow(clippy::expect_used)] // hardcoded constants; validity is exercised by tests
pub fn well_known_purpose_keys() -> PurposeKeys {
    PurposeKeys {
        tx_io_sk: secp256k1::SecretKey::from_str(
            "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
        )
        .expect("valid well-known tx_io secret key"),
        tx_io_pk: secp256k1::PublicKey::from_str(
            "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
        )
        .expect("valid well-known tx_io public key"),
        rng_ikm: WELL_KNOWN_RNG_IKM,
    }
}

/// Fetch purpose keys: built locally when `--enclave.mock-server` is set, otherwise
/// fetched from the key custodian's Unix socket (`--enclave.custodian-socket`).
/// This must be called before building the node components.
/// Panics if purpose keys cannot be fetched from the custodian.
///
/// Total fetch attempts = `config.retries` + 1 (one initial attempt plus `retries`
/// re-attempts); the `while failures <= config.retries` loop encodes this directly.
#[allow(clippy::panic)] // Intentional panic on fetching keys failure - purpose keys are required
pub async fn fetch_purpose_keys<T>(config: &T) -> PurposeKeys
where
    T: AsRef<EnclaveArgs>,
{
    let config = config.as_ref();
    if config.mock_server {
        info!(target: "reth::cli", "Using built-in well-known purpose keys (no TEE)");
        return well_known_purpose_keys();
    }

    info!(target: "reth::cli", "Fetching purpose keys from the custodian socket");
    let mut failures = 0;
    while failures <= config.retries {
        match fetch_keys_from_custodian(&config.custodian_socket, config.enclave_timeout).await {
            Ok(purpose_keys) => {
                info!(target: "reth::cli", "Successfully fetched purpose keys from the custodian");
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
    panic!(
        "FATAL: Failed to fetch purpose keys from the custodian on boot after {failures} failures"
    );
}

/// One custodian fetch attempt: connect, fetch the tx-io and rng key material at
/// [`PURPOSE_KEY_EPOCH`], and decode it. Bounded end-to-end by `timeout_seconds`
/// so a stalled custodian fails the attempt instead of hanging the boot.
async fn fetch_keys_from_custodian(
    socket: &Path,
    timeout_seconds: u64,
) -> eyre::Result<PurposeKeys> {
    tokio::time::timeout(Duration::from_secs(timeout_seconds), async {
        let mut custodian = CustodianClient::connect(socket).await?;
        let tx_io = custodian.get_tx_io_keypair(PURPOSE_KEY_EPOCH).await?;
        let rng = custodian.get_rng_ikm(PURPOSE_KEY_EPOCH).await?;
        purpose_keys_from_custodian_bytes(&tx_io, &rng)
    })
    .await
    .map_err(|_| eyre::eyre!("custodian fetch timed out after {timeout_seconds}s"))?
}

/// Decode the custodian's raw key bytes into the typed purpose-key bundle.
fn purpose_keys_from_custodian_bytes(
    tx_io: &TxIoKeypairBytes,
    rng: &RngIkmBytes,
) -> eyre::Result<PurposeKeys> {
    Ok(PurposeKeys {
        tx_io_sk: secp256k1::SecretKey::from_byte_array(&tx_io.sk)?,
        tx_io_pk: secp256k1::PublicKey::from_byte_array_compressed(&tx_io.pk)?,
        rng_ikm: rng.ikm,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // Test code - expect on failure is acceptable

    use super::*;
    use std::time::Instant;

    /// sanvil (whose mock arm serves keys built from the sample-key fns) must produce
    /// these exact keys: `rng_ikm` is a consensus input via the RNG precompile, so
    /// drift splits the chain, and divergence from sanvil breaks dev-tooling interop.
    /// This holds for as long as dev networks share keys with anvil.
    #[test]
    fn well_known_purpose_keys_match_enclave_crate() {
        use seismic_crypto::{
            get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
            get_unsecure_sample_secp256k1_sk,
        };

        let ours = well_known_purpose_keys();
        assert_eq!(ours.tx_io_sk, get_unsecure_sample_secp256k1_sk());
        assert_eq!(ours.tx_io_pk, get_unsecure_sample_secp256k1_pk());
        assert_eq!(ours.rng_ikm, get_unsecure_sample_schnorrkel_keypair().secret.to_bytes());
    }

    /// The hardcoded `tx_io_pk` must actually be `tx_io_sk`'s public key — wallets
    /// ECDH against the published key, the node decrypts with the secret one.
    #[test]
    fn well_known_tx_io_keypair_is_consistent() {
        let keys = well_known_purpose_keys();
        assert_eq!(keys.tx_io_pk, keys.tx_io_sk.public_key(&secp256k1::Secp256k1::new()));
    }

    /// The clap default must stay in lockstep with the custodian's canonical socket
    /// path (the images-side unit files bind it there); node-core hardcodes the
    /// string because it cannot depend on `seismic-custodian-ipc`.
    #[test]
    fn default_custodian_socket_matches_ipc_crate() {
        assert_eq!(
            EnclaveArgs::default().custodian_socket,
            Path::new(seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH)
        );
    }

    /// The custodian's raw key bytes decode to exactly the well-known keys when
    /// fed the sample derivations.
    #[test]
    fn custodian_bytes_decode_to_purpose_keys() {
        use seismic_crypto::{
            get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
            get_unsecure_sample_secp256k1_sk,
        };

        let tx_io = TxIoKeypairBytes {
            sk: get_unsecure_sample_secp256k1_sk().secret_bytes(),
            pk: get_unsecure_sample_secp256k1_pk().serialize(),
        };
        let rng = RngIkmBytes { ikm: get_unsecure_sample_schnorrkel_keypair().secret.to_bytes() };

        let keys = purpose_keys_from_custodian_bytes(&tx_io, &rng).expect("decode purpose keys");
        let expected = well_known_purpose_keys();
        assert_eq!(keys.tx_io_sk, expected.tx_io_sk);
        assert_eq!(keys.tx_io_pk, expected.tx_io_pk);
        assert_eq!(keys.rng_ikm, expected.rng_ikm);
    }

    /// A stalled custodian socket (accepts connections but never replies) must make
    /// the fetch error within the configured `enclave_timeout`, not hang the boot.
    #[tokio::test]
    async fn enclave_timeout_bounds_a_stalled_fetch() {
        let dir = tempfile::tempdir().expect("create socket directory");
        let socket = dir.path().join("custodian.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind unix listener");
        tokio::spawn(async move {
            // The Vec exists only to keep the sockets alive; it is never read.
            #[allow(clippy::collection_is_never_read)]
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // keep the connection open without ever responding
            }
        });

        let started = Instant::now();
        let result = fetch_keys_from_custodian(&socket, 1).await;

        assert!(result.is_err(), "stalled fetch should error, not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "fetch should be bounded by enclave_timeout, took {:?}",
            started.elapsed()
        );
    }
}
