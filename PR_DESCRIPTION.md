# feat: purpose-key rotation — reth-side groundwork (Phases 0–1)

## Summary

Implements everything of the purpose-key rotation design that can land in seismic-reth alone: the keyring refactor, a dormant on-chain rotation watcher, the pool expiry boundary rule, and a new `seismic_getKeyEpochInfo` RPC endpoint. The full design is included as `docs/design/purpose-key-rotation.md` — review that first; this PR is its Phase 0 and the reth half of Phase 1.

**Zero behavior change on every running network.** The `KeyRotationRegistry` predeploy does not exist yet, so its address reads as empty storage, the rotation schedule stays empty, `epoch_for_block` ≡ 0, and every new code path no-ops. This was verified end-to-end: the full e2e suite passes unchanged, and a dev node boots serving the same well-known key as before.

## Why

Today reth fetches purpose keys (the tx-io keypair + RNG ikm) once at boot at a hardcoded `PURPOSE_KEY_EPOCH = 0`, then freezes them behind `OnceLock` + `Box::leak` + `&'static` for the process lifetime. There is no way to react to a key rotation without a redesign of the plumbing. The custodian side has been rotation-ready all along — its IPC derives keys per-epoch (`GetTxIoKeypair{epoch}` / `GetRngIkm{epoch}`, HKDF from the root key) — but nothing on the node side can learn that an epoch advanced or hold more than one epoch's keys.

The design (see the spec) is **announce-then-activate**: an admin transaction to a `KeyRotationRegistry` predeploy schedules `(epoch E+1, activation block A)` with a mandatory delay; nodes fetch the new epoch's keys from their local custodian during the window; from block `A`, execution deterministically switches. Epochs are event-driven — there is no fixed epoch length.

## What's in this PR

### `reth-seismic-keys` (new crate, `crates/seismic/keys`)

The shared foundation, sitting below txpool/rpc/node:

- `RotationSchedule` / `RotationEntry` — the validated, append-only rotation history (dense epochs, strictly increasing activations) implementing the normative `epoch_for_block(B) = max{epoch : activation ≤ B, else 0}` function. Merges reject divergence and regression instead of adopting them.
- `PurposeKeyring` — epoch → keys behind shared swappable state (`Arc<PurposeKeyring>`). Old epochs are **never evicted** (historical sync needs them). Missing keys are a hard `MissingEpochKeys` error — consumers must never substitute another epoch (wrong `rng_ikm` forks the state root; wrong `tx_io_sk` flips `decryption_failed` receipts).
- `registry` — the predeploy's protocol constants: address `0x1000…0007` (next free in the predeploy family; `…0006` is the ops whitelist sentinel, `…0003` is retired), storage-slot derivation, packed-entry decoding, and the `RotationAnnounced` topic. **This module is a lockstep mirror of the not-yet-written `KeyRotationRegistry.sol`** — the decode fixtures are the anchor; if the contract lands with a different shape, this module changes with it in the same manifest-`ref` bump.

### Keyring plumbing (`refactor(node)!`, behavior-neutral)

- `OnceLock<PurposeKeys>` + `leak_purpose_keys` replaced by `OnceLock<Arc<PurposeKeyring>>`; the keyring flows structurally through `SeismicNode::new` → executor/pool builders.
- The EVM config still takes `&'static PurposeKeys` (that signature lives in `alloy-seismic-evm`) via a documented `epoch0_static` bridge — **the executor stays pinned to epoch 0 in this PR**. Un-pinning it is rollout Phase 2 and requires the `alloy-seismic-evm` factories to adopt the keyring.
- `SeismicApi` / `EthApiExt` read keys through the keyring per request instead of holding boot-time snapshots (a snapshot would silently go stale at the first rotation).
- `fetch_purpose_keys` is reimplemented over an epoch-parameterized, non-panicking `fetch_epoch_keys`; `well_known_purpose_keys_at(epoch)` extends the built-in source with a deterministic dev derivation for epochs > 0 (epoch 0 returns the exact existing constants — the sanvil-lockstep tests are untouched). The epoch > 0 derivation is self-consistent only and flagged TODO pending coordination with sanvil/the dev custodian (spec open question 4).

### Rotation watcher (dormant)

`crates/seismic/node/src/rotation.rs`, spawned from `SeismicExecutorBuilder::build_evm`:

- **Storage is the source of truth** (the canon-state broadcast drops notifications on lag): the watcher re-reads the registry's rotations array at task start, on every reorg, on `RotationAnnounced` log hints, and unconditionally every 256 blocks.
- Newly announced epochs' keys are fetched from the custodian with retries until activation (the announcement delay buys the time). If activation arrives without keys, execution stalls on `MissingEpochKeys` and self-heals when a fetch succeeds — never a fallback key.
- Boot reconciliation runs before launch and **fails the boot** if an announced epoch's keys can't be fetched within the bounded retry budget — same fail-fast policy as the epoch-0 boot fetch. Covers nodes offline across a rotation and snap-synced nodes.
- Exports a `seismic.rotation.pending_unfetched_epochs` gauge for rotation-drill alerting.
- Deviation from the spec draft, recorded in §5.3: spawned from the executor builder rather than `launch_add_ons`, because `AddOnsContext` has no channel for the parsed `PurposeKeysArgs` while the executor builder already receives the keyring and args structurally.

### Pool boundary rule (`feat(txpool)`)

While a rotation with activation `A` is pending, admission rejects seismic transactions with `expires_at_block >= A` (new `SeismicTxError::ExpiryCrossesRotation`, with a wallet-actionable message). Admitted transactions therefore always expire before the boundary, so the **existing** freshness eviction drains every old-key transaction exactly at activation — no new eviction code, no tx wire-format change, no epoch field in the envelope. The validator reads only the keyring's schedule (`pending()`), never key material.

### `seismic_getKeyEpochInfo` (`feat(rpc)`)

```json
{
  "currentEpoch": 0,
  "activationBlock": 0,
  "teePublicKey": "028e76…a0",
  "pendingRotation": { "epoch": 1, "activationBlock": 12345, "teePublicKey": "03ab…" }
}
```

Wallets poll this to pre-fetch the next key, switch encryption exactly at activation, and set `expires_at_block` values that clear the boundary rule. `pendingRotation.teePublicKey` appears once the node's watcher has fetched the epoch (usually right after announcement). `seismic_getTeePublicKey` keeps its wire shape and simply follows the keyring.

## Explicitly out of scope (future PRs / repos)

- `KeyRotationRegistry.sol` + genesis manifest entry (contracts repo; must match `reth-seismic-keys::registry`).
- Activation enforcement in the block executor — per-block key selection, `MissingEpochKeys → BlockExecutionError` (`alloy-seismic-evm` / `seismic-revm`), and the hardfork gate (spec Phase 2).
- The RPC AEAD grace-retry at the boundary (dead code until activation can happen; TODO in `EthApiExt::tx_io_sk`).
- Custodian epoch-ceiling hardening (spec §9).

## Testing

- 248 tests pass across all seismic crates, including the full 111-test node e2e suite, unchanged.
- New units: schedule invariants + epoch-for-block edges (incl. the state-height-independence property), keyring idempotence/conflict/missing-epoch behavior, registry slot/packing fixtures (anchored on `keccak256(uint256(1))` and an independent big-endian hex word), pool boundary predicate, epoch-info assembly across announce → fetch → activate.
- CI parity run locally: `cargo +nightly fmt --check`, seismic strict clippy (new crate covered by the `reth-seismic*` glob — no unwrap/expect/indexing/panic), workspace clippy on pinned 1.91.1 with `-D warnings --locked`.
- Smoke test: dev node boots with `--seismic.purpose-keys-source built-in`, serves the unchanged TEE key and the new epoch-info endpoint reporting the dormant state.
- Not runnable in this repo by design: watcher fetch against a real announcement (needs the contract) and activation enforcement (Phase 2). `dprint` / `zepter` were unavailable locally — flagging for CI.

## Commits

Reviewable in order:

1. `docs: add purpose-key rotation design spec`
2. `feat(seismic-keys): add epoch-keyed purpose keyring and rotation schedule`
3. `refactor(node)!: replace static purpose keys with Arc<PurposeKeyring>` ← behavior-neutral
4. `feat(node): add dormant key-rotation watcher and boot reconciliation`
5. `feat(txpool): reject seismic txs whose expiry crosses a pending rotation`
6. `feat(rpc): add seismic_getKeyEpochInfo`
7. `docs: sync rotation spec with the reth-side implementation`

## Reviewer notes

- The spec's **open questions (§11)** need owners: live-testnet contract insertion strategy, announce authority, custodian epoch ceiling, shared dev derivation, per-network `MIN_ACTIVATION_DELAY`.
- The registry address/layout/topic in `reth-seismic-keys::registry` is a **proposal the contract must honor** (or this crate changes with it) — worth explicit sign-off from whoever writes the Solidity.
- `epoch0_static` leaks one `PurposeKeys` copy per node construction, same as the old `leak_purpose_keys` — bounded, and deleted entirely in Phase 2.
