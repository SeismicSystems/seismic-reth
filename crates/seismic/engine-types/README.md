# reth-seismic-engine-types

Engine API wire types and header conventions shared between seismic-reth (execution) and
Summit (consensus).

Seismic block headers are **stock Ethereum headers**: `timestamp` is in Unix seconds and the
block hash is the standard `keccak(rlp(header))`. The sub-second component of the block time,
`timestampMillisPart` (`0..1000`), is carried in the first two bytes of `extraData`:

```text
extraData = [timestampMillisPart: u16 big-endian][builder data: 0..=30 bytes]
```

`block time (ms) = timestamp * 1000 + timestampMillisPart`. Consensus rejects headers whose
`extraData` is shorter than two bytes, longer than 32 bytes, or whose prefix is `>= 1000`.

## Wire format

Execution payloads (`engine_newPayloadV3/V4`, `engine_getPayloadV3/V4`) are the stock
`ExecutionPayloadV3`; the sub-second component is read from the payload's `extraData`.

`engine_forkchoiceUpdatedV3` payload attributes ([`SeismicPayloadAttributes`]) extend the stock
attributes with an explicit `timestampMillisPart` so consensus can request a sub-second block
time. Stock fields are flattened; the extra field is camel-cased and hex-quantity encoded:

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

## Helpers

- `split_timestamp_millis(ms) -> (seconds, part)` / `join_timestamp_millis(seconds, part)`:
  the canonical conversions. Consensus should split once at the Engine API boundary and keep
  working in milliseconds internally.
- `extra_data::encode_extra_data(part, builder_data)` /
  `extra_data::decode_timestamp_millis_part(extra_data)` /
  `extra_data::header_timestamp_millis(timestamp, extra_data)`: the `extraData` layout.

## Features

- default (`std`): stock `alloy` only. This is what Summit depends on (by git) — no
  seismic-alloy forks, no reth.
