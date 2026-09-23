# Purpose-key rotation

## Status and scope

Purpose keys rotate jointly: one epoch selects both the transaction-I/O keypair
and the RNG input key material. The registry is present in the checked-in dev
genesis. Registry constants, contract layout, genesis artifacts and network
activation policy must stay coordinated; an absent registry selects epoch zero.

This design replaces process-global execution schedules with parent-state
selection. It does not change key derivation, introduce root-key rotation, or
make mixed built-in/custodian deployments interoperable.

The implementation spans this repository and
[seismic-evm](https://github.com/SeismicSystems/seismic-evm). Both `alloy-evm` and
`alloy-seismic-evm` are pinned to
[`bbf2c03fb9af9e6d59bcc97d01cd9452340f1437`](https://github.com/SeismicSystems/seismic-evm/commit/bbf2c03fb9af9e6d59bcc97d01cd9452340f1437),
which includes the shared registry decoder, frozen block selections and retryable
execution errors. Local Cargo overrides are no longer needed for this change.

## 1. Consensus invariant

Given identical parent state and a block, nodes must select the same epoch and
produce identical execution results, regardless of prior branch exposure or
extra cached key material, once the required epoch's keys are available.
Missing material is an explicit local execution failure, never a different selection.

The normative function for block `B` is:

```text
epoch(B, parent_state):
    schedule := decode registry in this block's actual parent state
    return the last entry whose activation_block <= B, or epoch 0
```

The database is the executor's database, including its branch overlays. It is not
`client.latest()`, a canonical schedule snapshot, or a maximum observed tip.
Read and decode failures are errors; they do not mean an empty registry.

The distinction matters even for a shallow reorg before activation. An announcement
on orphan branch A can activate epoch 1 at height 200, while replacement branch B
has no announcement, or schedules epoch 1 at height 300. At block 200 those branches
legitimately select different epochs. A node previously exposed to A must agree with
a clean node when both execute B.

Append-only registry storage is append-only **along one branch**, not across
competing branches. A long activation delay helps operations and wallet propagation;
it does not make a process-global append-only schedule consensus-safe. No local
finality observation participates in epoch selection.

## 2. Registry protocol

The shared decoder lives in
[alloy-seismic-evm's registry module](https://github.com/SeismicSystems/seismic-evm/blob/bbf2c03fb9af9e6d59bcc97d01cd9452340f1437/crates/seismic-evm/src/registry.rs).
`reth-seismic-keys::registry` re-exports it so the watcher and executor use the same
constants, packed-word validation and schedule invariants.

| Location | Content |
| --- | --- |
| `0x1000000000000000000000000000000000000007` | Registry predeploy |
| Slot `0` | Admin address |
| Slot `1` | `rotations.length` |
| `keccak256(uint256(1)) + i` | Packed rotation entry `i` |

Each entry is one storage word containing, from least to most significant bits,
`epoch: u64`, `activationBlock: u64`, `announcedAtBlock: u64`, and zero padding.
Epochs are dense: entry `i` is epoch `i + 1`. Activation heights strictly increase,
and each activation is strictly after its announcement. The decoder caps the
array at 100,000 entries and rejects malformed packing, overflow and invalid
schedules. Registry slots are public storage; decoding uses their values.

The admin calls `announceRotation(uint64 activationBlock)`. The contract's
minimum delay and pending-rotation restrictions are independent of reconciliation:
a canonical reorg can remove or replace a previously observed announcement.

## 3. Separate material from metadata

`PurposeKeyring` holds two independently synchronized responsibilities:

- **Additive key inventory:** epoch-to-`PurposeKeys` material plus deduplicated
  execution fetch requests. Material is never evicted: historical execution needs
  old tx-I/O secret keys and RNG inputs. Re-inserting identical material is
  idempotent. Different material for an existing epoch is rejected, preserving
  the original bytes.
- **Replaceable canonical view:** `{ head_hash, head_number, schedule }`, published
  together under one lock. RPC and pool policy consume this view. It is not
  authoritative for block execution.

The canonical API replaces the entire view. There is no independent tip update,
append-only publication API or schedule-coverage shortcut. Shorter histories,
equal-length replacements and lower canonical heads are valid reconciliation
results. Extra keys retained from an orphan are harmless inventory, not evidence
that an epoch should activate.

RPC key discovery snapshots the metadata once when assembling a response, rather
than separately reading current epoch, activation and pending epoch across possible
reconciliations. Key lookups may happen afterward because material is additive and
conflicting replacements are forbidden. The pool obtains its pending boundary from
one coherent metadata view.

## 4. Frozen execution attempts

Before pre-execution state changes, the Seismic block executor initializes the
EVM's key selection. Initialization:

1. Loads the registry account before storage access (required by revm's `State`).
2. Reads and validates the complete schedule through that EVM's database.
3. Resolves the epoch for the block number and retrieves exactly that epoch's keys.
4. Stores an owned selection and initializes the RNG from it.

The EVM remembers the selection or initialization failure for the lifetime of that
attempt. The executor also retains an owned selection for transaction decryption.
Both transaction execution entry points use that selection, not shared metadata.
A concurrent canonical update cannot change either the RNG input or the tx-I/O key
mid-block. A pre-execution failure leaves the executor uninitialized; transaction
execution and finalization reject an uninitialized executor.

Raw RPC EVMs use the same fallible initialization before their first transaction.
Factories do not read or publish schedules during construction. There is no
best-effort current-epoch or zero-key fallback during transaction execution.

A retry creates a fresh execution attempt against the same parent state. Inserting
a missing key does not silently rehabilitate a failed EVM instance or change a
successful instance's frozen selection.

## 5. Fetching and liveness

### Boot

Epoch zero is obtained before node construction. Once a provider is available,
boot reconciliation reads a canonical view pinned to a head hash and fetches its
missing announced epochs with the configured bounded retry budget. Failure aborts
startup explicitly.

### Watcher and worker

`crates/seismic/node/src/rotation.rs` runs two cancellable futures:

- **Canonical reconciliation:** reads on startup, every canonical notification,
  and a 60-second safety-net timer. It obtains the head identity, opens state at
  that hash, decodes the schedule and checks the head identity again. A head change
  during the read causes a retry rather than mixed metadata. The serialized watcher
  atomically replaces the view, including reorgs to shorter or lower histories.
- **Material fetcher:** polls once per second and fetches the deduplicated union of
  missing canonical epochs and missing execution-requested epochs. Failed fetches
  leave requests queued. Successful insertion removes the request. It never
  publishes an activation schedule.

A slow custodian fetch does not prevent the canonical future from reconciling
notifications. Publication can still lag the chain, as with any asynchronous
watcher; execution is independent of that lag. No database provider or keyring lock
is held across a custodian await.

Execution queues only the epoch selected from its actual parent state. It does
not require keys for future or orphan-only announcements. Staged sync therefore
can discover a required epoch that is absent from the watcher's canonical view,
without publishing the speculative branch's schedule.

### Retry classification

Missing key material becomes a retryable internal `BlockExecutionError`, not a
validation error. The generic retry marker is wrapped in the existing arbitrary
internal-error variant so it does not enlarge the error enum.

- Pipeline sync discards the failed write transaction, waits one second and retries
  from its checkpoint. It must not unwind or mark the block bad for this error.
- Engine payload processing returns `SYNCING` without populating the invalid-header
  cache or terminating the engine. A later payload retry can succeed after fetching.
- Registry I/O/decoding errors remain explicit errors and are not disguised as
  missing-key requests.

This is an availability mechanism, not a guarantee that any custodian outage will
heal: the selected epoch must eventually become available with the correct material,
and Engine API callers must retry the payload.

## 6. Simulation isolation

`PurposeKeyring::snapshot` now means an isolated **simulation handle**, not a copied
canonical execution schedule. It shares additive material, starts with no canonical
metadata and cannot enqueue live fetch requests. `SeismicEvmConfig` gives both
factories the same request-local handle.

Each simulated block selects from its simulated parent's database overlay. An
announcement in simulated block 1 can therefore affect simulated block 2 or a later
activation, but can never affect the live canonical view. A copied live schedule is
not treated as an authority, even if the live node previously saw an orphan.

Missing simulated keys fail explicitly without asking the custodian to fetch them.
Keys independently fetched by the live worker may become available to a new
simulation attempt; they cannot change an already-initialized attempt. Failed
simulations and successful simulations both leave live activation metadata and
fetch requests untouched.

The existing `eth_simulateV1` integration fixture uses an authorized admin and the
real registry bytecode, not forbidden RPC storage overrides.

## 7. Transaction-I/O boundary and RPC policy

Consensus decryption is strict: each transaction uses the epoch selected for its
including block. There is no old-key retry or dual-key grace window in execution.
An old-epoch ciphertext force-included after activation follows the deterministic,
metered decryption-failure path.

The pool's pending-rotation boundary rejects seismic transactions whose
`expires_at_block >= activation_block`; pre-activation traffic must expire before
the boundary. RPC key discovery advertises the canonical current key and, when
known, the pending epoch's public key. Signed reads still decrypt their envelope
with the advertised current key; that RPC policy is separate from the RNG epoch
selected from the request's execution state.

## 8. Key-source assumption and known mismatch

Epoch-key inventory assumes a fixed root and a fixed derivation algorithm per
network. The pinned
[custodian implementation](https://github.com/SeismicSystems/enclave/blob/7dc159d50f7142466e0ac5c73e15d524d996b5b2/crates/custodian/src/custodian.rs)
uses HKDF-SHA256 with salt `seismic-purpose-derive-salt` and info
`seismic-purpose-{label} || epoch_be` to derive 32 bytes. The tx-I/O output is a
secp256k1 scalar; RNG material is the 64-byte result of Schnorrkel uniform
mini-secret expansion. With the same root, epoch and algorithm, these outputs are
deterministic.

Built-in epoch zero preserves the shared well-known constants. Built-in epochs
above zero use the published root in `keys_source.rs` and directly expand **64
HKDF bytes** for RNG. This is **not** the custodian's 32-byte-then-Schnorrkel
algorithm, even if the roots match. Custodian epoch-zero derivation from an
arbitrary dev root also need not reproduce the well-known constants.

Do not mix these sources on a rotating network. Rejecting a conflicting insertion
protects one process's inventory, but cannot detect two clean nodes initialized
from incompatible sources. The schedule fix neither resolves that mismatch nor
implements root rotation. Coordinating built-in, custodian and sanvil derivation
requires a separate compatibility decision; never silently change historical RNG
material as part of this fix.

## 9. Performance

There is initially no schedule cache. The full decoder performs one length-slot
read plus one read per historical rotation, once per EVM execution attempt, before
block state changes—not once per transaction. The registry account is also loaded.

Benchmark before optimizing. Possible later designs include validated targeted
lookup or a bounded in-memory cache keyed by actual parent hash. Such a cache must
be reconstructible and evictable; it mainly helps repeated attempts against one
parent rather than unique new parents. Height alone, schedule length, a future
activation and the highest observed tip are not safe cache keys.

## 10. Validation coverage and release requirements

Regression coverage is split by responsibility:

- `crates/seismic/evm/tests/rotation_reorg.rs`: competing parent states, clean versus
  exposed nodes, replacement activation, missing-orphan keys, retry after insertion,
  registry failures and per-attempt read counting.
- Seismic-EVM keyring/block tests: additive material, conflicting insertions,
  deduplicated requests, simulation handles, initialization requirements and both
  transaction APIs under an interleaved watcher update.
- Rotation watcher unit tests: shorter/equal-length/lower-head replacement and
  request-driven fetching without publication.
- `crates/seismic/node/tests/rotation_reorg.rs`: real Engine API forkchoice reorg
  and canonical watcher reconciliation, retaining fetched historical material.
- Existing `key_rotation` e2e simulation: real registry announcements in private
  multi-block overlays, including failure at an unfetched activation.
- Engine-tree and pipeline tests: retryable internal errors must not poison the
  invalid-header cache or trigger bad-block unwind.

Fixture-level execution, worker and retry-controller tests cover separate layers;
they are not a multi-node catch-up drill through a real custodian outage. Before
release, run that drill, formatting, strict Seismic Clippy and the relevant test
suites in both repositories. Verify the Reth integration against the published
Seismic-EVM pin without local overrides.
