//! Tools to obtain purpose keys: from the local key custodian's Unix socket, or built
//! locally from the well-known keys when running without a TEE.
use std::{path::Path, time::Duration};

use alloy_seismic_evm::{secp256k1, PurposeKeys};
use reth_node_core::args::{PurposeKeysArgs, PurposeKeysSource};
use seismic_custodian_ipc::{CustodianClient, RngIkmBytes, TxIoKeypairBytes};
use tracing::{info, warn};

/// The key epoch this node fetches its purpose keys at. Epochs only advance on an
/// explicit operator-triggered rotation (a consensus event); until that mechanism
/// exists every node derives at epoch 0.
const PURPOSE_KEY_EPOCH: u64 = 0;

/// Fetch purpose keys: built locally with `--seismic.purpose-keys-source built-in`, otherwise
/// fetched from the key custodian's Unix socket (`--seismic.custodian.socket`).
/// This must be called before building the node components.
/// Panics if purpose keys cannot be fetched from the custodian.
///
/// Total fetch attempts = `custodian.retries` + 1 (one initial attempt plus `retries`
/// re-attempts); the `while failures <= custodian.retries` loop encodes this directly.
#[allow(clippy::panic)] // Intentional panic on fetching keys failure - purpose keys are required
pub async fn fetch_purpose_keys<T>(config: &T) -> PurposeKeys
where
    T: AsRef<PurposeKeysArgs>,
{
    let config = config.as_ref();
    if config.source == PurposeKeysSource::BuiltIn {
        info!(target: "reth::cli", "Using built-in well-known purpose keys (no TEE)");
        // Real keys with zero secrecy, not mocks: on pre-TEE networks — the live testnet
        // included — every node boots with this source, so the well-known keys are the
        // consensus-visible network keys. Wallets encrypt to the tx-io public key, sync
        // decrypts history with the secret one, and the ikm seeds the RNG precompile.
        // TODO: these are the only keys reth can run without a custodian; there is no way
        // to input other key material. By mainnet launch, a pre-TEE mainnet must not run
        // keys published on GitHub — needs a per-network keypair provisioned outside
        // source control (e.g. a `file` key source), while sanvil/dev networks stay on the
        // well-known keys.
        return PurposeKeys::well_known();
    }

    let custodian = &config.custodian;
    info!(target: "reth::cli", "Fetching purpose keys from the custodian socket");
    let mut failures = 0;
    while failures <= custodian.retries {
        match fetch_keys_from_custodian(&custodian.socket, custodian.timeout_seconds).await {
            Ok(purpose_keys) => {
                info!(target: "reth::cli", "Successfully fetched purpose keys from the custodian");
                return purpose_keys;
            }
            Err(e) => {
                warn!(target: "reth::cli", "Failure to fetch purpose keys {}/{}: {}", failures, custodian.retries, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    custodian.retry_seconds.into(),
                ))
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

/// Decode the custodian's raw key bytes into the typed purpose-key bundle, rejecting a
/// mismatched tx-io keypair — a node must never advertise a public key whose traffic it
/// cannot decrypt.
fn purpose_keys_from_custodian_bytes(
    tx_io: &TxIoKeypairBytes,
    rng: &RngIkmBytes,
) -> eyre::Result<PurposeKeys> {
    let secp = secp256k1::Secp256k1::new();
    let tx_io_sk = secp256k1::SecretKey::from_byte_array(&tx_io.sk)?;
    let tx_io_pk = secp256k1::PublicKey::from_byte_array_compressed(&tx_io.pk)?;
    let derived_pk = tx_io_sk.public_key(&secp);
    eyre::ensure!(
        tx_io_pk == derived_pk,
        "custodian served a mismatched tx-io keypair: public key {tx_io_pk} is not the secret key's ({derived_pk})"
    );
    Ok(PurposeKeys {
        tx_io: secp256k1::Keypair::from_secret_key(&secp, &tx_io_sk),
        rng_ikm: rng.ikm,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // Test code - expect on failure is acceptable

    use super::*;
    use std::time::Instant;

    /// The clap default must stay in lockstep with the custodian's canonical socket
    /// path (the images-side unit files bind it there); node-core hardcodes the
    /// string because it cannot depend on `seismic-custodian-ipc`.
    #[test]
    fn default_custodian_socket_matches_ipc_crate() {
        assert_eq!(
            PurposeKeysArgs::default().custodian.socket,
            Path::new(seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH)
        );
    }

    /// The custodian's raw key bytes decode to exactly the well-known bundle when the
    /// custodian serves the well-known key material.
    #[test]
    fn custodian_bytes_decode_to_purpose_keys() {
        use seismic_crypto::{well_known_rng_ikm, well_known_tx_io_keypair};

        let keypair = well_known_tx_io_keypair();
        let tx_io = TxIoKeypairBytes {
            sk: keypair.secret_key().secret_bytes(),
            pk: keypair.public_key().serialize(),
        };
        let rng = RngIkmBytes { ikm: well_known_rng_ikm() };

        let keys = purpose_keys_from_custodian_bytes(&tx_io, &rng).expect("decode purpose keys");
        let expected = PurposeKeys::well_known();
        assert_eq!(keys.tx_io, expected.tx_io);
        assert_eq!(keys.rng_ikm, expected.rng_ikm);
    }

    /// A custodian response whose public key is not the secret key's must be rejected
    /// at decode time instead of booting a node that advertises a key it cannot
    /// decrypt for.
    #[test]
    fn mismatched_custodian_keypair_is_rejected() {
        use seismic_crypto::{well_known_rng_ikm, well_known_tx_io_keypair};

        let other_sk = secp256k1::SecretKey::from_byte_array(&[1; 32]).expect("valid secret key");
        let tx_io = TxIoKeypairBytes {
            sk: other_sk.secret_bytes(),
            pk: well_known_tx_io_keypair().public_key().serialize(),
        };
        let rng = RngIkmBytes { ikm: well_known_rng_ikm() };

        let err = purpose_keys_from_custodian_bytes(&tx_io, &rng)
            .expect_err("mismatched keypair must be rejected");
        assert!(err.to_string().contains("mismatched tx-io keypair"), "unexpected error: {err}");
    }

    /// A stalled custodian socket (accepts connections but never replies) must make
    /// the fetch error within the configured `timeout_seconds`, not hang the boot.
    #[tokio::test]
    async fn custodian_timeout_bounds_a_stalled_fetch() {
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
            "fetch should be bounded by timeout_seconds, took {:?}",
            started.elapsed()
        );
    }
}
