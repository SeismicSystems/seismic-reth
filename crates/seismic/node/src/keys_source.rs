//! Tools to obtain purpose keys: from the local key custodian's Unix socket, or built
//! locally from the well-known keys when running without a TEE.
use std::{path::Path, time::Duration};

use alloy_seismic_evm::{secp256k1, PurposeKeys};
use reth_node_core::args::{PurposeKeysArgs, PurposeKeysSource};
use seismic_custodian_ipc::{CustodianClient, RngIkmBytes, TxIoKeypairBytes};
use tracing::{info, warn};

/// The genesis key epoch. Boot always fetches epoch 0; later epochs are fetched by
/// the rotation watcher as on-chain rotation announcements appear
/// (`docs/design/purpose-key-rotation.md`).
const PURPOSE_KEY_EPOCH: u64 = 0;

/// The HKDF salt the custodian uses for purpose-key derivation; mirrored here so the
/// built-in dev derivation stays structurally identical to the custodian's scheme.
const PURPOSE_DERIVE_SALT: &[u8] = b"seismic-purpose-derive-salt";

/// The publicly-known root the built-in source derives epoch > 0 keys from.
/// Exactly 32 bytes, zero secrecy by design (dev networks only).
const DEV_WELL_KNOWN_ROOT: [u8; 32] = *b"seismic-well-known-dev-root-key!";

/// The well-known purpose keys for `epoch`, used with
/// `--seismic.purpose-keys-source built-in`.
///
/// Epoch 0 returns [`PurposeKeys::well_known`] — the live keys of every pre-TEE
/// network, kept in lockstep with sanvil via the shared `seismic-crypto` crate.
/// Epochs > 0 derive deterministically from [`DEV_WELL_KNOWN_ROOT`] with the
/// custodian's HKDF scheme.
// TODO: coordinate the epoch > 0 derivation with sanvil and the dev custodian
// (spec §5.5 / open question 4). Until then it is only self-consistent: the
// custodian's rng derivation still routes through a schnorrkel expansion for
// epoch 0 backward compat, so a dev custodian would disagree with this at
// epoch > 0. Nothing can announce a rotation before the KeyRotationRegistry
// contract ships, so no network can hit the divergence yet.
pub fn well_known_purpose_keys_at(epoch: u64) -> eyre::Result<PurposeKeys> {
    if epoch == 0 {
        return Ok(PurposeKeys::well_known());
    }
    let tx_io_sk = derive_dev_tx_io_sk(epoch)?;
    let rng_ikm = derive_dev_purpose_bytes::<64>("rng-precompile", epoch, 0)?;
    Ok(PurposeKeys {
        tx_io: secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &tx_io_sk),
        rng_ikm,
    })
}

/// HKDF-SHA256 expansion mirroring the custodian's derivation:
/// `info = "seismic-purpose-{label}" || epoch_be` (plus a retry counter byte when
/// nonzero, used only for the negligible invalid-scalar case below).
fn derive_dev_purpose_bytes<const N: usize>(
    label: &str,
    epoch: u64,
    counter: u8,
) -> eyre::Result<[u8; N]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(PURPOSE_DERIVE_SALT), &DEV_WELL_KNOWN_ROOT);
    let mut info = format!("seismic-purpose-{label}").into_bytes();
    info.extend_from_slice(&epoch.to_be_bytes());
    if counter > 0 {
        info.push(counter);
    }
    let mut out = [0u8; N];
    hk.expand(&info, &mut out)
        .map_err(|e| eyre::eyre!("hkdf expand for {label} at epoch {epoch}: {e}"))?;
    Ok(out)
}

/// Derives the dev tx-io secret key for `epoch`. A 32-byte expansion is an invalid
/// secp256k1 scalar with negligible probability; the counter loop keeps the function
/// total without a panic path.
fn derive_dev_tx_io_sk(epoch: u64) -> eyre::Result<secp256k1::SecretKey> {
    for counter in 0..=u8::MAX {
        let bytes = derive_dev_purpose_bytes::<32>("tx-io", epoch, counter)?;
        if let Ok(sk) = secp256k1::SecretKey::from_byte_array(&bytes) {
            return Ok(sk);
        }
    }
    Err(eyre::eyre!("no valid tx-io scalar for epoch {epoch} in 256 derivation attempts"))
}

/// Fetch the boot (epoch-0) purpose keys: built locally with
/// `--seismic.purpose-keys-source built-in`, otherwise fetched from the key
/// custodian's Unix socket (`--seismic.custodian.socket`).
/// This must be called before building the node components.
/// Panics if purpose keys cannot be fetched from the custodian.
#[allow(clippy::panic)] // Intentional panic on fetching keys failure - purpose keys are required
pub async fn fetch_purpose_keys<T>(config: &T) -> PurposeKeys
where
    T: AsRef<PurposeKeysArgs>,
{
    match fetch_epoch_keys(config, PURPOSE_KEY_EPOCH).await {
        Ok(purpose_keys) => purpose_keys,
        Err(e) => panic!("FATAL: Failed to fetch purpose keys on boot: {e}"),
    }
}

/// Fetch the purpose keys for `epoch`: derived locally with
/// `--seismic.purpose-keys-source built-in`, otherwise fetched from the custodian
/// socket with one bounded retry pass (total attempts = `custodian.retries` + 1).
///
/// Unlike [`fetch_purpose_keys`] this returns an error instead of panicking, so the
/// rotation watcher can keep retrying across its own loop while boot-time callers
/// escalate as they see fit.
pub async fn fetch_epoch_keys<T>(config: &T, epoch: u64) -> eyre::Result<PurposeKeys>
where
    T: AsRef<PurposeKeysArgs>,
{
    let config = config.as_ref();
    if config.source == PurposeKeysSource::BuiltIn {
        info!(target: "reth::cli", epoch, "Using built-in well-known purpose keys (no TEE)");
        // Real keys with zero secrecy, not mocks: on pre-TEE networks — the live testnet
        // included — every node boots with this source, so the well-known keys are the
        // consensus-visible network keys. Wallets encrypt to the tx-io public key, sync
        // decrypts history with the secret one, and the ikm seeds the RNG precompile.
        // TODO: these are the only keys reth can run without a custodian; there is no way
        // to input other key material. By mainnet launch, a pre-TEE mainnet must not run
        // keys published on GitHub — needs a per-network keypair provisioned outside
        // source control (e.g. a `file` key source), while sanvil/dev networks stay on the
        // well-known keys.
        return well_known_purpose_keys_at(epoch);
    }

    let custodian = &config.custodian;
    info!(target: "reth::cli", epoch, "Fetching purpose keys from the custodian socket");
    let mut failures = 0;
    loop {
        match fetch_keys_from_custodian(&custodian.socket, custodian.timeout_seconds, epoch).await {
            Ok(purpose_keys) => {
                info!(target: "reth::cli", epoch, "Successfully fetched purpose keys from the custodian");
                return Ok(purpose_keys);
            }
            Err(e) => {
                warn!(target: "reth::cli", epoch, "Failure to fetch purpose keys {}/{}: {}", failures, custodian.retries, e);
                failures += 1;
                if failures > custodian.retries {
                    return Err(eyre::eyre!(
                        "failed to fetch purpose keys for epoch {epoch} from the custodian after {failures} attempts: {e}"
                    ));
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    custodian.retry_seconds.into(),
                ))
                .await;
            }
        }
    }
}

/// One custodian fetch attempt: connect, fetch the tx-io and rng key material at
/// `epoch`, and decode it. Bounded end-to-end by `timeout_seconds` so a stalled
/// custodian fails the attempt instead of hanging the caller.
async fn fetch_keys_from_custodian(
    socket: &Path,
    timeout_seconds: u64,
    epoch: u64,
) -> eyre::Result<PurposeKeys> {
    tokio::time::timeout(Duration::from_secs(timeout_seconds), async {
        let mut custodian = CustodianClient::connect(socket).await?;
        let tx_io = custodian.get_tx_io_keypair(epoch).await?;
        let rng = custodian.get_rng_ikm(epoch).await?;
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

    /// Epoch 0 of the built-in derivation must be exactly the well-known keys —
    /// the live pre-TEE network keys cannot change out from under running networks.
    #[test]
    fn well_known_at_epoch_zero_is_the_well_known_keys() {
        let at_zero = well_known_purpose_keys_at(0).expect("epoch 0 derivation");
        let well_known = PurposeKeys::well_known();
        assert_eq!(at_zero.tx_io, well_known.tx_io);
        assert_eq!(at_zero.rng_ikm, well_known.rng_ikm);
    }

    /// Epoch > 0 derivation must be deterministic (all built-in nodes agree)
    /// and distinct per epoch.
    #[test]
    fn well_known_at_later_epochs_is_deterministic_and_distinct() {
        let one_a = well_known_purpose_keys_at(1).expect("epoch 1 derivation");
        let one_b = well_known_purpose_keys_at(1).expect("epoch 1 derivation");
        assert_eq!(one_a.tx_io, one_b.tx_io);
        assert_eq!(one_a.rng_ikm, one_b.rng_ikm);

        let two = well_known_purpose_keys_at(2).expect("epoch 2 derivation");
        assert_ne!(one_a.tx_io, two.tx_io);
        assert_ne!(one_a.rng_ikm, two.rng_ikm);

        let zero = PurposeKeys::well_known();
        assert_ne!(one_a.tx_io, zero.tx_io);
        assert_ne!(one_a.rng_ikm, zero.rng_ikm);
    }

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
        let result = fetch_keys_from_custodian(&socket, 1, PURPOSE_KEY_EPOCH).await;

        assert!(result.is_err(), "stalled fetch should error, not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "fetch should be bounded by timeout_seconds, took {:?}",
            started.elapsed()
        );
    }
}
