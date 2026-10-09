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

Only the V3/V4 method versions are served. The shared types live in
`crates/seismic/engine-types` (`reth-seismic-engine-types`), which depends on stock `alloy`
only so Summit can consume it without the Seismic forks. See its README for the wire format.

The payload id commits to the sub-second component, so two builds that differ only in
`timestampMillisPart` get distinct ids.

## Hard fork

Moving the sub-second precision out of `timestamp` changes the header RLP/hash and the
database encoding of headers: it is a regenesis for every existing network. Genesis hashes
are pinned in `crates/seismic/chainspec/src/lib.rs` and printed by
`seismic-reth genesis-hash --chain <spec>`; Summit's `eth_genesis_hash` must match.

## Known gap (until the EVM forks catch up)

`BlockEnv.timestamp` is in seconds and the fork EVM crates have no slot for the sub-second
component yet, so `TIMESTAMPMS` currently returns `timestamp * 1000`. Once seismic-revm /
seismic-evm carry a `timestamp_millis_part` in the block environment, the node fills it from
the header and `TIMESTAMPMS` becomes exact. The `timestamp-in-seconds` feature of those forks
is enabled unconditionally by this workspace in the meantime.
