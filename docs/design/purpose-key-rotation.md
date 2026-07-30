# Purpose-Key Rotation

Status: **draft / proposal** — for team review. Nothing in this document is implemented.

This spec describes how the network rotates its purpose keys (the tx-io keypair and
the RNG ikm): an on-chain announcement made by an authorized operator schedules a new
key epoch, every node fetches the new epoch's keys from its local key custodian during
the announcement window, and execution deterministically switches to the new keys at
the activation block.

## 1. Background and motivation

Today reth fetches purpose keys exactly once, at boot, at a hardcoded epoch:

- `crates/seismic/node/src/keys_source.rs:13` — `const PURPOSE_KEY_EPOCH: u64 = 0`,
  with the doc comment "Epochs only advance on an explicit operator-triggered rotation
  (a consensus event); until that mechanism exists every node derives at epoch 0."
- The custodian side is already rotation-ready: `GetTxIoKeypair{epoch}` and
  `GetRngIkm{epoch}` derive per-purpose keys as
  `HKDF-SHA256(root_key, salt="seismic-purpose-derive-salt", info="seismic-purpose-{label}" || epoch_be)`.
  The custodian is stateless with respect to epochs — it serves any `u64` an
  ACL-permitted caller asks for. No wire change is needed for rotation.

Two consensus facts constrain every design choice below:

1. **`rng_ikm` is a consensus input.** The RNG precompile's HKDF uses it as ikm; its
   output feeds contract state. Two nodes executing the same block with different ikm
   produce different state roots. The epoch active for a block must therefore be a
   deterministic function of chain state, identical on every node, forever.
2. **`tx_io_sk` decrypts history.** Re-executing old blocks (sync from genesis,
   `stage` runs, pruned-node backfill) decrypts each block's transactions with the key
   that was active *when the block was produced*, and a failed decryption is itself
   consensus-visible (the `decryption_failed` receipt field). Old epochs' keys must
   remain available forever; rotation adds keys, it never removes them.

A third practical fact shapes the plumbing: keys are currently frozen at boot behind
`OnceLock<PurposeKeys>` + `Box::leak` (`crates/seismic/node/src/purpose_keys.rs`) and
fanned as `&'static PurposeKeys` into `SeismicEvmFactory` (rng) and
`SeismicBlockExecutorFactory` (tx-io decrypt) — both in the external
`alloy-seismic-evm` repo — plus by-value clones in the RPC layer
(`crates/seismic/node/src/node.rs:385-404`). There is no hot-swap path; building one
is the first phase of this work.

## 2. Overview

One network-wide **epoch counter**, starting at 0, drives derivation of both purposes
(tx-io and rng) — a *joint* epoch. The custodian's per-purpose epoch parameters simply
both receive the same value.

> Why joint rather than per-purpose: the realistic rotation trigger is "derived key
> material may have leaked from a node," and both purposes live in the same process
> memory, so they are compromised together. Independent epochs would double the
> on-chain schedule, the epoch-for-block function, the keyring, and the test matrix
> for no defensive gain. The custodian IPC's per-purpose flexibility stays intact and
> unused.

A rotation is three steps:

1. **Announce.** An authorized admin calls the on-chain `KeyRotationRegistry`,
   appending `(epoch E+1, activationBlock A)` with `A` at least
   `MIN_ACTIVATION_DELAY` blocks in the future.
2. **Fetch.** Each node's rotation watcher observes the announcement and fetches epoch
   E+1's keys from its local custodian socket — idempotently, with retries, well
   before `A`.
3. **Activate.** From block `A` onward, block execution selects epoch E+1's keys.
   Blocks below `A` keep using the keys of the epoch active at their height, forever.

**Non-goals.**

- Root-key rotation (custodian-side; changes every epoch's derivation — a separate,
  much harder problem).
- Snapshot-key rotation (`GetSnapshotKey` is consumed by the snapshot service, not
  reth; out of scope).
- Revocation/eviction of old epochs (forbidden — see §1).
- Automatic rotation cadence (the mechanism supports scheduled rotations; the policy
  is out of scope).
- Transaction wire-format changes (`TxSeismicElements` gets no epoch field — see §6).

## 3. On-chain protocol

### 3.1 The `KeyRotationRegistry` predeploy

A **new predeploy** in the `0x1000…000N` family, added to
`crates/seismic/chainspec/res/genesis/manifest.toml` with its artifact fetched from
the contracts repo (bump `ref`, regenerate and commit `dev.json` + hash, as the
manifest header prescribes).

Proposed address: `0x1000000000000000000000000000000000000007`.
(`…0001`–`…0002` are the measurement registry/authority, `…0004`–`…0005` are
Directory/Intelligence, `…0006` is the ops-whitelist tx sentinel — it has code in the
dev genesis and is hardcoded as `WHITELIST_TX_SENTINEL` in
`crates/rpc/rpc-layer/src/signature_auth_layer.rs:51` — and `…0003` appears retired;
do not reuse either.)

Why a new contract rather than extending `ProtocolParams`: the Params storage layout
is already load-bearing — ops auth reads slot 0 raw at boot
(`crates/node/builder/src/rpc.rs:1113-1147`) — and rotation needs an append-only
array plus its own authorization, which is a poor fit for a params blob.
`MeasurementRegistry` is the precedent for adding a registry predeploy.

**Storage layout** (the node reads raw slots, per the ops-auth precedent; no
`eth_call` on any hot path):

| Slot | Content |
| --- | --- |
| `0` | `admin` (address) — the announce authority |
| `1` | `rotations.length` (Solidity dynamic-array length slot) |
| `keccak256(1) + i` | element `i`: one word packing `(epoch: u64, activationBlock: u64, announcedAtBlock: u64)` |

**Contract-enforced invariants** (these keep the node-side function trivial):

- `announceRotation(uint64 activationBlock)` is admin-only.
- Epochs are auto-assigned and dense: entry `i` is epoch `i + 1` (epoch 0 is the
  pre-rotation genesis epoch and never appears in the array).
- `activationBlock >= block.number + MIN_ACTIVATION_DELAY`.
- `activationBlock` strictly greater than the previous entry's.
- At most one rotation pending at a time (the last entry's activation must have
  passed before a new announcement is accepted).
- Append-only; **no cancel or reschedule in v1** (cancellation breaks monotonicity
  and complicates the wallet story — revisit only with a concrete need).

**Event** (low-latency hint only — storage is the source of truth, see §5.3):

```solidity
event RotationAnnounced(uint64 indexed epoch, uint64 activationBlock);
```

### 3.2 Block-number activation, not timestamps

Activation is a **block number**. This follows two existing seismic precedents, both
chosen because the host wall clock is untrusted in TEE deployments: the ops-auth
whitelist expires by canonical block number
(`crates/rpc/rpc-layer/src/signature_auth_layer.rs`), and transaction freshness is
block-based (`expires_at_block`, `recent_block_hash`,
`SEISMIC_TX_RECENT_BLOCK_LOOKBACK = 100`).

Block-number activation also makes the epoch function **reorg-invariant by
construction**: competing blocks at the same height always compute the same epoch, so
a reorg near the boundary can never flip a block's epoch (§7).

### 3.3 `MIN_ACTIVATION_DELAY` (K)

K is the guarantee that every node (and every wallet) has time to act on an
announcement before it takes effect. It must exceed, with generous margin:

1. worst-case reorg depth / finality lag — so an activated announcement is always
   final (this *replaces* any runtime finality check, see §5.3);
2. the custodian fetch retry budget (`--seismic.custodian.retries` ×
   `retry-seconds`; minutes at most);
3. wallet propagation — wallets poll for the pending rotation and must be ready to
   switch encryption keys at `A` (give hours);
4. the pool freshness window (`SEISMIC_TX_RECENT_BLOCK_LOOKBACK = 100` blocks) plus
   typical `expires_at_block` horizons, so the boundary rule in §6 has room.

Proposal: a genesis-configurable per-network constant with a floor of **7200 blocks**
(≈2h at 1s blocks); operational runbooks use ≥24h for real rotations; dev chains use
a small value (e.g. 32) so e2e tests can cross a boundary quickly. Concrete
per-network values are an open question (§11).

### 3.4 The epoch-for-block function (normative)

```text
epoch_for_block(B):
    entries := the rotations array, read from any canonical state at height >= B-1
    return max { e.epoch : e.activationBlock <= B }     // 0 if none, or registry absent
```

- `epoch_for_block(0) = 0`. Any block before the first activation is epoch 0. A chain
  without the registry deployed is epoch 0 forever — pre-rotation networks are
  unchanged and the function is total.
- **State-height independence** (the property everything else leans on): because the
  array is append-only and every entry satisfies
  `activationBlock ≥ announcedAtBlock + K`, an entry present in state at some height
  H but *not* at height B−1 was necessarily announced after B−1, so its activation is
  `> B−1+K ≥ B`. It therefore cannot affect `epoch_for_block(B)`. Reading the array
  from **any** state at height ≥ B−1 — the block's actual pre-state, a snap-sync
  checkpoint, or the live tip — yields the same answer for B. This is what lets a
  tip-cached schedule, a snap-synced node, and historical re-execution all agree.
- The state formally in scope at execution of block B is the post-state of B−1 (the
  block's pre-state), which the executor always has; the property above makes a
  cached schedule an equivalent, cheaper read (§5.4).

## 4. The keyring

The `&'static PurposeKeys` plumbing is replaced end-to-end by a shared, swappable
**epoch-keyed keyring**, defined in `alloy-seismic-evm` next to `PurposeKeys`
(the block executor factory there is its primary consumer):

```rust
pub struct RotationEntry { pub epoch: u64, pub activation_block: u64 }
pub struct RotationSchedule(Vec<RotationEntry>);   // sorted, dense epochs, append-only

pub struct PurposeKeyring {
    inner: RwLock<KeyringState>,   // reads are per-block, not per-op; RwLock suffices
}
struct KeyringState {
    schedule: RotationSchedule,
    keys: BTreeMap<u64, PurposeKeys>,   // epoch -> keys; NEVER evicted
}

impl PurposeKeyring {
    pub fn single_epoch(keys: PurposeKeys) -> Self;   // built-in mode, tests, Phase 0
    pub fn epoch_for_block(&self, block: u64) -> u64;
    pub fn keys_for_block(&self, block: u64) -> Result<PurposeKeys, MissingEpochKeys>;
    pub fn current(&self) -> (u64, PurposeKeys);      // max activation <= known tip
    pub fn pending(&self) -> Option<(u64, u64)>;      // (epoch, activation) not yet active
    pub fn insert_epoch(&self, epoch: u64, keys: PurposeKeys);   // idempotent, additive
    pub fn apply_schedule(&self, s: RotationSchedule);           // append-only merge
}
```

Shared everywhere as `Arc<PurposeKeyring>`. A concrete type, deliberately not a
`PurposeKeyProvider` trait: the factories are already concrete over `PurposeKeys`, a
trait would push generics through `SeismicEvmConfig`'s already-heavy signature, and
`single_epoch` covers every test need.

Replacement sites for `&'static PurposeKeys` / owned snapshots:

- `crates/seismic/node/src/purpose_keys.rs` — delete `leak_purpose_keys`; the global
  fallback becomes `OnceLock<Arc<PurposeKeyring>>` (still needed by the `stage` CLI
  path and `SeismicNode::default()` tests, same roles as today).
- `crates/seismic/node/src/node.rs:80/89/117/512` — `SeismicNode`,
  `SeismicExecutorBuilder`.
- `crates/seismic/node/src/lib.rs:30-35`, `crates/seismic/evm/src/lib.rs:57-83` —
  `seismic_evm_config` / `SeismicEvmConfig::new`.
- Cross-repo: `SeismicEvmFactory` and `SeismicBlockExecutorFactory` in
  `alloy-seismic-evm` (see §5.1), `SeismicChain` in `seismic-revm`.
- RPC: `EthApiExt` and `SeismicApi` hold the keyring instead of by-value snapshots
  (§8) — a snapshot would silently become stale at the first rotation.

## 5. Node architecture

### 5.1 Per-block key selection in the block executor

All consensus-side key selection happens in **one place**: at block start inside the
`SeismicBlockExecutorFactory` executor (in `alloy-seismic-evm`), where
`SeismicChain::set_parent_block_hash` is already called:

```rust
let keys = keyring.keys_for_block(block_number)?;   // MissingEpochKeys -> BlockExecutionError
chain.set_rng_key(keys.rng_ikm);                     // setter already exists in seismic-revm
// stash keys.tx_io_sk for this block's per-tx plaintext_copy(&sk, signer) calls
```

With the rng key set per-block on `SeismicChain`, `SeismicEvmFactory` no longer needs
key material at `create_evm` time at all — its key field is removed, shrinking the
keyed surface to a single component. Do *not* select keys in reth's `evm_with_env`
(`crates/seismic/evm/src/lib.rs:242-248`): pipeline sync, live validation, and payload
building all flow through the block executor, so the block-start hook covers every
path with one code site.

While touching `seismic-revm`, land its existing TODO flattening
`SeismicChain.live_rng_key` from `schnorrkel::Keypair` to `[u8; 64]` (no schnorrkel
cryptography is performed on it; it is HKDF ikm only).

> Verify at implementation time: the exact factory signatures at the pinned
> `alloy-seismic-evm` rev (`Cargo.toml:796`) and the current `live_rng_key` type at
> the pinned `seismic-revm` rev — the locally checked-out copies of both repos lag
> the pins.

**Missing-key policy: hard error, no fallback.** `MissingEpochKeys` maps to a
`BlockExecutionError`. Substituting another epoch's keys is never acceptable: the
wrong `rng_ikm` silently forks the state root, and the wrong `tx_io_sk` flips
`decryption_failed` receipts — both are consensus splits, strictly worse than a
stall. The node stalls at that height with an actionable error
("purpose keys for epoch N not fetched from custodian") and **self-heals**: the
watcher keeps retrying the fetch (§5.3), and execution resumes the moment the keys
arrive. Stall, don't crash — a crash-looping node redoes boot work; a stalled node
recovers the instant the custodian comes back.

### 5.2 Why not an ExEx, and why not an engine hook

- **ExEx**: its WAL, backfill, and inverted-notification machinery exist for durable
  derived state that must be unwound on reorgs. A custodian fetch is idempotent and
  additive (§5.3), so there is nothing to unwind. Meanwhile an installed ExEx gates
  the pruner, applies pipeline backpressure, panics the node if the task errors, and
  can only be installed at the binary level — all cost, no benefit here.
- **Engine/payload-validation hook**: a custodian IPC round-trip (with retries)
  inside block validation would stall the engine and make block validity depend on
  local socket availability — a liveness and consensus-split risk. The engine and
  executor are where rotation is *enforced* (§5.1); the *fetch* must live off the
  validation path.

### 5.3 The rotation watcher

New module `crates/seismic/node/src/rotation.rs`, spawned from
`SeismicAddOns::launch_add_ons` (`crates/seismic/node/src/node.rs:369`) via
`ctx.node.task_executor().spawn_critical(...)`, modeled directly on the existing
canon-state consumer `maintain_seismic_freshness`
(`crates/seismic/txpool/src/maintain.rs:84`, spawned at `node.rs:647-654`). Inputs:
the provider (`StateProviderFactory + CanonStateSubscriptions`), the
`Arc<PurposeKeyring>`, and the custodian config (`PurposeKeysArgs`).

Loop:

1. **Reconcile** — run at task start, on every `Reorg` notification, on any
   stream-lag error, and unconditionally every ~256 blocks: read
   `rotations.length` (one raw storage read at the registry address) from latest
   state; if it exceeds the cached schedule, read the new elements,
   `apply_schedule`, and fetch keys for any epoch missing from the keyring.
   Storage is the source of truth precisely because `canonical_state_stream()` is a
   broadcast channel that **drops notifications on lag** — the design must not
   depend on seeing every log.
2. **Hint** — on `Commit`, scan the notification's in-memory receipts
   (`ExecutionOutcome::logs`) for the `RotationAnnounced` topic from the registry
   address; on a hit, reconcile immediately. Logs are latency optimization only.
3. **Fetch** — reuse the shape of `fetch_keys_from_custodian`
   (`crates/seismic/node/src/keys_source.rs:97-109`) parameterized by epoch:
   `get_tx_io_keypair(epoch)` + `get_rng_ikm(epoch)`, same per-attempt timeout, same
   pk == sk·G consistency check. Unlike the boot fetch, retry **indefinitely until
   activation** (the announcement bought ≥ K blocks of margin), escalating
   `warn!` → `error!` as the tip approaches the activation height, and export a
   `seismic.rotation.pending_unfetched_epochs` gauge for alerting.
4. **If activation arrives without keys** — nothing special in the watcher: the
   executor's hard error (§5.1) stalls the node; the watcher keeps retrying; on
   success, execution resumes without a restart. Fail-closed and self-healing.

**Finality is guaranteed by K, never checked in consensus.** Finality is a local,
non-deterministic observation; putting a "is the announcement finalized?" predicate
into the epoch function would poison determinism. Instead the contract's
`MIN_ACTIVATION_DELAY ≫ finality lag` guarantees every *activated* announcement was
final long ago. The watcher may optionally consume
`ForkChoiceSubscriptions::finalized_block_stream()` purely to log a critical warning
if an announcement is somehow still unfinalized as activation nears — an operational
signal, not a consensus input. Fetching keys for an announcement that later reorgs
away is harmless: the keyring is additive and idempotent.

### 5.4 Boot sequence

Today `fetch_purpose_keys` runs before the node builder, with no chain state
available. Rotation splits boot into two stages:

1. **Pre-builder** (unchanged location, `bin/seismic-reth/src/main.rs:17`): fetch
   **epoch 0** from the custodian (or use built-in keys), seed
   `Arc<PurposeKeyring>` with it, hand it to `SeismicNode::new`. This preserves the
   "fail before doing anything expensive if the custodian is unreachable" property.
2. **Schedule reconciliation in `SeismicExecutorBuilder::build_evm`**
   (`node.rs:517-537` — the provider is available and it runs before any
   execution): read the rotations array from latest local state; for each announced
   epoch missing from the keyring, fetch with the existing *bounded* retry budget
   and **panic on exhaustion, exactly like today's boot fetch** — at boot, unlike at
   runtime, there is no announced-in-advance grace window, so fail fast and loud.
   Fetch *all* announced epochs, including not-yet-activated ones. This covers the
   node that was offline across a rotation and the snap-synced node.
3. The watcher (§5.3) takes over from there.

**Pipeline-sync catch-up across a rotation announced after the local head.** Staged
(pipeline) sync executes blocks without per-block canonical notifications, so a node
far behind could execute past an activation whose announcement entered state
*mid-sync* — after the boot reconciliation read. The authoritative fix lives in the
block executor: on a schedule-cache miss risk, re-read the rotations array from the
**block's parent state** (the executor holds the state handle right there). The
cached schedule is a provably-sufficient fast path whenever it already contains an
entry with `activationBlock > B` — by the state-height-independence property (§3.4),
the cache then cannot be missing anything relevant to B. Worst case this costs one
storage read per block during deep catch-up; zero on live nodes.

### 5.5 Built-in (dev) mode

`--seismic.purpose-keys-source built-in` keeps working unchanged:
`PurposeKeyring::single_epoch(well_known_purpose_keys())`. For rotation e2e tests on
dev chains, extend to `well_known_purpose_keys_at(epoch)`:

- epoch 0 returns today's exact constants, preserving the sanvil-interop assertion
  (`keys_source.rs:139-150` — `rng_ikm` is a consensus input, drift splits the dev
  chain);
- epoch > 0 derives deterministically, ideally with the custodian's own HKDF scheme
  applied to a published dev root, so built-in mode, sanvil, and a dev custodian all
  agree. This requires confirming what root the custodian's dev/mock arm uses so
  that epoch 0 output equals the well-known keys — open question §11.

## 6. The tx-io boundary

**Decision: consensus decryption is keyed strictly by
`epoch_for_block(including_block)`. No dual-key grace window in the executor.**

Determinism is *not* the discriminator here — a fixed "try sk(E+1), fall back to
sk(E) for G blocks" rule would also be a pure function of chain state and therefore
consensus-safe. The real arguments for strictness:

- **Security.** Rotation exists because sk(E) may be compromised. A grace window
  keeps sk(E) authoritative for *new* traffic after activation, extending exactly
  the exposure rotation is meant to end.
- **Simplicity.** One key selection per block start (§5.1) versus per-tx
  try/fallback, doubled AEAD attempts, and ambiguous receipt semantics.

**The UX cost is near zero because the envelope already solves it.**
`TxSeismicElements` carries no epoch or key hint (its fields are the client's
ephemeral `encryption_pubkey`, `encryption_nonce`, `message_version`,
`recent_block_hash`, `expires_at_block`, `signed_read`), and adding one is a wire
format change across seismic-alloy and every wallet — rejected. Instead, rotation
rides `expires_at_block`, which is *already* enforced at pool admission
(`crates/seismic/txpool/src/validator.rs` freshness checks), continuously by the
freshness-eviction task (`maintain_seismic_freshness`), and at RPC:

> **Boundary rule.** While a rotation with activation block `A` is pending, the pool
> validator and `eth_sendRawTransaction` reject any seismic transaction with
> `expires_at_block >= A`, with a distinct error: *"transaction expiry crosses the
> key-rotation boundary at block A; shorten expiry, or re-encrypt to the new key
> after activation."*

Consequences:

- Every admitted old-epoch transaction has `expires_at_block < A`, so the existing
  eviction task automatically drains all old-epoch transactions from the pool
  exactly at activation. No new eviction code, no epoch tagging in the pool.
- An honest builder can never include a pk(E)-encrypted transaction at height ≥ A.
  A malicious or buggy builder force-including one produces a deterministic
  `decryption_failed` receipt on all nodes — the same failure mode that exists today
  for garbage ciphertext. Consensus is safe; the sender's fee loss is the rare,
  self-inflicted worst case.
- Wallets: poll `seismic_getKeyEpochInfo` (§8); before `A`, cap
  `expires_at_block ≤ A−1` (or simply retry on the rejection error); at/after `A`,
  encrypt to the new pk. Given K ≥ hours and the 100-block `recent_block_hash`
  lookback already forcing wallets to build transactions against fresh tip data, the
  boundary is a non-event in practice.

Implementation note: the pool validator needs visibility of `pending()` — give it
the `Arc<PurposeKeyring>`. It reads the schedule only; the pool continues to hold no
secret key material.

## 7. Consensus and sync considerations

- **`rng_ikm` flips exactly at `A`.** An off-by-one-block disagreement is a chain
  split. The single block-start selection point (§5.1) driven by the normative
  function (§3.4) is the entire defense; the historical-determinism e2e test (§10)
  is the proof.
- **Reorg across the boundary.** Activation is by block number, so competing blocks
  at the same height always compute the same epoch — a reorg cannot flip any
  block's epoch. Announcements themselves are protected by `K ≫ reorg depth`: the
  epoch of any executable block depends only on entries announced ≥ K blocks
  earlier. The watcher still fully re-reads storage on `Reorg` notifications as
  belt-and-braces.
- **Snap/checkpoint sync.** The complete rotation history lives in the append-only
  array in *current* state, so a snap-synced node reads the full schedule from its
  checkpoint state (state-height independence, §3.4) and fetches all epochs at boot
  — a handful of custodian round-trips.
- **Offline across a rotation.** Boot reconciliation (§5.4) plus the executor's
  parent-state fallback cover both the "announcement already in local state" and the
  "announcement enters state mid-catch-up" cases.
- **Stalls.** Any missing-key condition stalls block processing with a clear error
  and self-heals when the custodian serves the epoch.

## 8. RPC changes

- **`SeismicApi`** (`crates/seismic/rpc/src/eth/ext.rs`): holds the keyring.
  `seismic_getTeePublicKey` keeps its wire shape (a bare public key) and returns
  `current()`'s pk — the value simply changes at activation, no `V2` endpoint
  needed.
- **New `seismic_getKeyEpochInfo`** returning
  `{ currentEpoch, activationBlock, teePublicKey,
     pendingRotation: { epoch, activationBlock, teePublicKey } | null }`
  so wallets can pre-fetch the next key, switch exactly at `A`, and set compliant
  `expires_at_block` values (§6). The pending pk is available because the watcher
  fetches announced epochs immediately (§5.3).
- **`EthApiExt`** signed-read handlers (`eth_call`, `eth_callMany`,
  `eth_simulateV1`, `eth_estimateGas`): decrypt with `current()` — **the tip epoch,
  not the target block's epoch** — because wallets always encrypt to the currently
  advertised pk and `validate_seismic_freshness` already pins requests to the live
  tip window regardless of the queried `BlockId`. RPC is not consensus, so a UX
  grace is safe *here*: if AEAD decryption fails within
  `SEISMIC_TX_RECENT_BLOCK_LOOKBACK` blocks after an activation, retry once with the
  previous epoch's sk. Cheap, consensus-irrelevant, and removes the only
  user-visible race at the boundary.

## 9. Custodian-side changes

**Strictly required: none.** The IPC already serves arbitrary epochs.

Recommended follow-up hardening (separately scheduled):

- **Epoch ceiling.** The custodian serves any `u64` today, so a compromised host
  that can still reach the socket can pre-fetch *future* epochs — meaning rotation
  defends against leaked derived keys only once the custodian enforces
  "serve epochs ≤ current + 1". The custodian has no chain view; ceiling bumps would
  ride an attested operator action or signed governance statement. The reth-side
  design is unaffected either way.
- Per-epoch request audit logging (cheap; immediately useful during rotation
  drills).

## 10. Rollout, sequencing, and testing

### Cross-repo sequencing (git-pin bump order)

1. **seismic-revm** — `live_rng_key: Keypair → [u8; 64]` (existing TODO); no
   rotation logic. Tag; bump pins downstream.
2. **alloy-seismic-evm** — `PurposeKeyring`, factory signatures
   (`&'static PurposeKeys → Arc<PurposeKeyring>`), block-start selection,
   `MissingEpochKeys`. Must be behavior-neutral for a single-epoch keyring. Tag;
   bump the `Cargo.toml:796` pin here.
3. **seismic-reth** — everything in §§4-8 (Phases 0-2 below).
4. **Contracts repo** — `KeyRotationRegistry.sol`; then seismic-reth bumps
   `manifest.toml` `ref` and commits the regenerated dev genesis + hash.
5. **sanvil / seismic-alloy / wallet SDK** — `seismic_getKeyEpochInfo` client types,
   per-epoch well-known derivation in sanvil's mock arm, wallet switch-at-A and
   expiry-cap behavior.

### Phases (each independently shippable)

- **Phase 0 — keyring indirection, zero behavior change.** Repos 1-2 land;
  seismic-reth replaces `OnceLock`/`Box::leak`/`&'static` with
  `Arc<PurposeKeyring>` seeded `single_epoch`; `epoch_for_block` returns 0
  unconditionally. Test fixtures updated mechanically
  (`crates/seismic/node/src/utils.rs:34`, `crates/seismic/evm/src/lib.rs:348/378`,
  `crates/seismic/fuzz/src/mock_keys.rs`, e2e).
- **Phase 1 — contract + watcher, fetch-only.** Registry in dev genesis; the watcher
  reconciles, fetches announced epochs, and emits metrics — but the executor stays
  pinned to epoch 0. Exercises the custodian multi-epoch path and the watcher in
  production shape with zero consensus risk; observable on dev/testnet.
- **Phase 2 — activation enforcement.** A new `SeismicHardfork` entry (after
  Mercury) with a **non-zero** `ForkCondition::Timestamp` (a zero-timestamp fork
  would change the genesis hash; dev chains regenerate genesis anyway). The fork
  gates executor epoch selection, the pool boundary rule, `seismic_getKeyEpochInfo`,
  and the RPC grace fallback. The fork-id change cleanly separates un-upgraded
  peers. Ships after Phase 1 has soaked.
- **Phase 3 — operationalization.** Rotation drills (dev, then testnet: announce →
  watch fetch metrics → cross activation → verify wallets); wallet SDK GA; runbook;
  optional custodian epoch-ceiling work; execute the live-testnet
  contract-insertion decision (§11.1).

### Testing

Unit:

- `epoch_for_block`: empty schedule; single rotation with B ∈ {A−1, A, A+1};
  multiple rotations; the state-height-independence property (schedules read at
  later heights answer identically for old blocks); `apply_schedule` rejects
  non-monotone input.
- Keyring: `insert_epoch` idempotence, `MissingEpochKeys`, concurrent read/update.
- Packed-slot decoding against a fixture generated from the actual Solidity layout.
- Pool: boundary-rule rejection iff a rotation is pending; expiry-driven drain at A
  through the existing freshness-eviction path.

Integration / e2e (dev chain):

- **Full rotation drill**: announce via admin tx → assert watcher fetch → cross A →
  assert: pre-A old-key tx executes; a force-included old-key tx post-A yields a
  `decryption_failed` receipt; the pool rejects `expires_at_block ≥ A`; a new-key tx
  executes post-A; RNG precompile output differs across A for identical inputs.
- **Historical determinism (the critical one)**: after the drill, wipe and re-sync a
  second node from genesis; assert identical state roots across the boundary. This
  proves epoch-for-block from historical state, old-epoch decryption, and old-ikm
  RNG reproduction all at once.
- Reorg at the boundary: two competing blocks at height A → identical epoch,
  identical roots given identical transactions.
- Offline node: stop before the announcement, restart after A → boot reconciliation
  fetches both epochs and the node catches up (covers the pipeline-sync path, §5.4).
- Custodian down at activation: kill the custodian before A with the epoch
  unfetched → the node stalls with the expected error; restore the custodian → the
  node resumes without a restart.

E2e key material: needs `well_known_purpose_keys_at(epoch)` (§5.5). Until the shared
dev derivation exists, rotation e2e can run against a real dev custodian binary over
a temp Unix socket (the custodian test harness exists in the enclave repo).

## 11. Open questions

1. **Live-testnet contract insertion.** The registry ships in genesis for new
   networks; for the already-running testnet: irregular state injection at the
   Phase 2 fork (EIP-2935-style), a governance deploy at a conventional address
   recorded via a ProtocolParams pointer, or accepting the feature only on networks
   launched after it. Needs an ops/testnet-policy call.
2. **Announce authority and policy.** ProtocolParams admin key, the ops-governance
   address, or a dedicated multisig? And is cancel/reschedule of a pending rotation
   needed in v1 (this spec says no)?
3. **Custodian epoch ceiling** (§9): priority and owner. Without it, rotation does
   not defend against a host that can still reach the custodian socket.
4. **Shared dev derivation ownership.** Who defines the per-epoch dev key derivation
   so built-in mode, sanvil, and the dev custodian agree — and does the custodian's
   mock root reproduce today's well-known keys at epoch 0?
5. **Concrete `MIN_ACTIVATION_DELAY` per network**, given actual block times and
   finality lag.
