# Block timestamps on Seismic

Seismic produces sub-second blocks. Rather than redefining the Ethereum header's
`timestamp` field (which every upstream component and every Ethereum tool reads as Unix
seconds), or adding a header field (which would make the block hash non-standard), the
sub-second component is carried inside the header's `extraData`.

## Header

Seismic blocks use the **stock Ethereum header** (`alloy_consensus::Header`). `timestamp` is
Unix seconds and the block hash is the standard `keccak(rlp(header))`.

```text
extraData = [timestampMillisPart: u16 big-endian][builder data: 0..=30 bytes]
```

- `timestampMillisPart` is `0..1000`; `block time (ms) = timestamp * 1000 + timestampMillisPart`.
- The remaining bytes are the usual free-form builder tag (`--builder.extradata`), capped at 30
  bytes instead of the stock 32 so the whole field stays within the 32-byte consensus limit.
- Genesis blocks carry a zero part: every committed genesis template starts its `extraData`
  with `0x0000`. An operator-supplied genesis file without the prefix is rejected at startup.
- Accessors live in `reth_seismic_primitives::header` (`SeismicBlockHeader` extension trait)
  and, for non-reth consumers, in `reth-seismic-engine-types::extra_data`.

Because the header is stock, any Ethereum tool can parse headers from JSON-RPC or raw RLP and
recompute and verify block hashes. This is header interoperability only: Seismic's trie
encoding is its own (`seismic-trie`) and `eth_getProof` is not served, so state/storage proof
tooling is out of scope. Tools that enforce Ethereum's *chain rules* (strictly increasing
seconds timestamps) still need to know about Seismic's millisecond ordering (below).

Everything upstream — hardfork activation, blob params, base-fee math, the transaction
pool, the `TIMESTAMP` opcode (`block.timestamp` in Solidity), logs' `blockTimestamp` — keeps
reading whole seconds. The `TIMESTAMPMS` opcode (`0x4B`) exposes milliseconds to contracts.

## Consensus rules

`SeismicConsensus` (`crates/seismic/node/src/consensus.rs`):

- Standalone: `extraData` must be 2..=32 bytes and its prefix `< 1000`. Checked on every
  header, including the first header of a range and headers decoded from files.
- Against the parent: consecutive blocks may share the same seconds `timestamp`; their
  millisecond block time must strictly increase.

## Engine API

Execution payloads (`engine_newPayloadV3/V4`, `engine_getPayloadV3/V4`) are the **stock**
Engine API types; the node reads the sub-second component from the payload's `extraData`.

Summit works in milliseconds internally and splits at the `engine_forkchoiceUpdatedV3`
boundary: the payload attributes are the stock fields plus `timestampMillisPart`
(`SeismicPayloadAttributes` in `crates/seismic/engine-types`, a stock-alloy-only crate so
Summit can consume it without the Seismic forks). The builder encodes the requested part into
the new block's `extraData`.

The payload id commits to the sub-second component, so two builds that differ only in
`timestampMillisPart` get distinct ids. Build requests validate the full millisecond timestamp
against the parent: same-second requests are valid only when their part increases. Equal or
earlier full timestamps and parts outside `0..1000` are rejected.

## Public RPC

Headers are served unchanged: there is no `timestampMillisPart` field. Consumers that need the
millisecond block time read the first two bytes of `extraData` (big-endian) and combine them
with `timestamp`.

## Hard fork

Moving the sub-second component into `extraData` (from the previous nested-header layout)
changes the header RLP/hash of every block including genesis: it is a regenesis for every
existing network. Genesis hashes are pinned in `crates/seismic/chainspec/src/lib.rs` and
printed by `seismic-reth genesis-hash --chain <spec>`; Summit's `eth_genesis_hash` must match.
Deployment genesis artifacts must set `"extraData": "0x0000"` (or `0x0000` followed by up to 30
bytes of tag).

## EVM execution

`SeismicBlockEnv` wraps the standard seconds-based `BlockEnv` and carries
`timestamp_millis_part`. The node populates it from the header's `extraData` when executing
existing headers and Engine API payloads, and from the payload attributes when building the
next block. The block assembler then encodes the environment's part into the new header, so
the header commits to exactly what `TIMESTAMPMS` exposed during execution.

Environment construction is infallible, so a malformed `extraData` decodes as a zero part
there. The engine tree executes a payload before running consensus checks on it, so such a
block may execute once with a zero part; consensus then rejects it and it is never admitted
to the canonical chain.

`TIMESTAMP` remains seconds. `TIMESTAMPMS` (`0x4B`, gas cost 2) returns the exact value
`timestamp * 1000 + timestamp_millis_part`.

## Beacon-root lookups

The Seismic beacon-root predeploy at `0x000f3df6d732807ef1319fb7b8bb8522d0beac02` uses
`TIMESTAMPMS` for its ring-buffer write index. Distinct same-second blocks therefore retain
separate roots. Its read calldata is an ABI-encoded **full millisecond timestamp**, not the
standard RPC `timestamp` alone. Consumers must recombine the RPC header's seconds and the
`extraData` prefix before querying it.
