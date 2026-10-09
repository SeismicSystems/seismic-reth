# reth-seismic-engine-types

Engine API wire types shared between seismic-reth (execution) and Summit (consensus).

Seismic block headers carry a standard Ethereum `timestamp` in Unix **seconds** plus a
separate sub-second component, `timestampMillisPart` (`0..1000`). These types extend the
stock Engine API payload attributes and execution payloads with that field so consensus can
drive millisecond block times without changing the meaning of any standard field.

## Wire format

Stock fields are flattened; the extra field is camel-cased and encoded as a hex quantity.

`engine_forkchoiceUpdatedV3` payload attributes ([`SeismicPayloadAttributes`]):

```json
{
  "timestamp": "0x6553f100",
  "timestampMillisPart": "0x7b",
  "prevRandao": "0x…",
  "suggestedFeeRecipient": "0x…",
  "withdrawals": [],
  "parentBeaconBlockRoot": "0x…"
}
```

`engine_newPayloadV3/V4` and `engine_getPayloadV3/V4` carry a
[`SeismicExecutionPayloadV3`]: the stock `ExecutionPayloadV3` plus `timestampMillisPart`.
`blockHash` is the hash of the full Seismic header, which commits to the sub-second
component, so it is **not** the hash of the stock fields alone.

Only the V3/V4 Engine API method versions are served by seismic-reth.

## Features

- default (`std`): stock `alloy` only. This is what Summit depends on (by git) — no
  seismic-alloy forks, no reth.
- `ssz`: SSZ encoding for [`SeismicExecutionPayloadV3`] (Summit hashes payloads in its block).
- `reth`: node-side integration — [`SeismicPayloadBuilderAttributes`], [`SeismicBuiltPayload`],
  block ⇄ payload conversions and the `reth` trait implementations.

## Helpers

`split_timestamp_millis(ms) -> (seconds, part)` and `join_timestamp_millis(seconds, part)` are
the canonical conversions; consensus should split once at the Engine API boundary and keep
working in milliseconds internally.
