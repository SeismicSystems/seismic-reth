# Block timestamps on Seismic

Seismic produces sub-second blocks. Rather than redefining the Ethereum header's
`timestamp` field (which every upstream component and every Ethereum tool reads as Unix
seconds), the block header carries a **separate** sub-second component.

## Header

```text
SeismicHeader {
    timestamp_millis_part: u64,   // 0..1000
    inner: alloy_consensus::Header,  // inner.timestamp is Unix seconds
}
```

- RLP: `[timestamp_millis_part, inner]`; the block hash is the keccak of that outer list, so
  it commits to the sub-second component.
- JSON (RPC): the standard header fields plus `timestampMillisPart`. `timestamp` is seconds.
- `timestamp_millis() = timestamp * 1000 + timestamp_millis_part`.
- Genesis blocks have a zero sub-second component.

Everything upstream — hardfork activation, blob params, base-fee math, the transaction
pool, the `TIMESTAMP` opcode (`block.timestamp` in Solidity), logs' `blockTimestamp` — keeps
reading whole seconds. The `TIMESTAMPMS` opcode (`0x4B`) exposes milliseconds to contracts.

## Consensus rule

Consecutive blocks may share the same seconds `timestamp`; their millisecond block time must
strictly increase (`SeismicConsensus`, `crates/seismic/node/src/consensus.rs`). The
out-of-range check (`timestamp_millis_part >= 1000`) rejects a header outright.

## Engine API

Summit works in milliseconds internally and splits at the Engine API boundary:

- `engine_forkchoiceUpdatedV3` attributes: stock fields + `timestampMillisPart`.
- `engine_newPayloadV3/V4`, `engine_getPayloadV3/V4`: the stock `ExecutionPayloadV3` +
  `timestampMillisPart`.

Only the V3/V4 method versions are served. The shared wire types live in
`crates/seismic/engine-types` (`reth-seismic-engine-types`), which depends on stock `alloy`
only so Summit can consume it without the Seismic forks; the node-side integration is
`crates/seismic/engine-primitives`. See the engine-types README for the wire format.

The payload id commits to the sub-second component, so two builds that differ only in
`timestampMillisPart` get distinct ids. Build requests validate the full millisecond timestamp
against the parent: same-second requests are valid only when their part increases. Equal or
earlier full timestamps and parts outside `0..1000` are rejected.

## Hard fork

Moving the sub-second precision out of `timestamp` changes the header RLP/hash and the
database encoding of headers: it is a regenesis for every existing network. Genesis hashes
are pinned in `crates/seismic/chainspec/src/lib.rs` and printed by
`seismic-reth genesis-hash --chain <spec>`; Summit's `eth_genesis_hash` must match.

## EVM execution

`SeismicBlockEnv` wraps the standard seconds-based `BlockEnv` and carries
`timestamp_millis_part`. The node populates both fields when executing existing headers,
building the next block from payload attributes, and executing Engine API payloads.
The full environment survives normal and inspected execution, system calls, RPC helpers,
and factory round trips. Shared Ethereum fields and overrides use the inner `BlockEnv`
without discarding the part.

`TIMESTAMP` remains seconds. `TIMESTAMPMS` (`0x4B`, gas cost 2) returns the exact value
`timestamp * 1000 + timestamp_millis_part`. The old `timestamp-in-seconds` feature is removed.
Converting a stock `BlockEnv` into `SeismicBlockEnv` assigns a zero part; it does not recover
precision missing from the caller.

## Beacon-root lookups

The Seismic beacon-root predeploy at `0x000f3df6d732807ef1319fb7b8bb8522d0beac02` uses
`TIMESTAMPMS` for its ring-buffer write index. Distinct same-second blocks therefore retain
separate roots. Its read calldata is an ABI-encoded **full millisecond timestamp**, not the
standard RPC `timestamp` alone. Consumers must recombine the RPC header's seconds and
`timestampMillisPart` before querying it. Changing only the lookup units cannot recover roots
written by an older, seconds-only EVM binary.
