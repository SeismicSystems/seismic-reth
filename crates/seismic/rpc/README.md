# Seismic RPC gas payments

RPC simulation uses the same registered-token metadata and balance-mode eligibility
as execution and pool admission. The shared rules and integer conversion helpers
are defined in [Seismic revm](https://github.com/SeismicSystems/seismic-revm/blob/seismic/crates/seismic/src/gas_token_registry.rs).

## Authentication and selector preservation

`gasPayment` is public, signed metadata on Seismic transactions. The registered
`eth_call`, `eth_estimateGas`, `eth_callMany`, and `eth_simulateV1` overrides accept
explicit selection only through authenticated, call-only signed reads (raw bytes
or signed typed data). Signed writes cannot be replayed through these endpoints.
Unsigned object-form requests may omit the setting or supply Auto; Native and
Token are rejected **before** sanitization rather than silently downgraded.
Unsigned sender, value, fee, type, and encryption fields retain their existing
sanitization. A standard transaction cannot carry a non-Auto selector.

The whole Seismic request survives decryption and conversion into the internal
network request. The request-to-EVM and simulated-transaction converters preserve
both selection and signed-read intent. Node-side signing remains unsupported.

## Gas allowance

Allowance reads the database supplied by the requested simulation, not an
independent latest-state provider. It reserves the actual native transaction value
first. Tokens fund only gas, never value, and balances are never combined:

| Selector | Allowance reads and capacity |
| --- | --- |
| Auto | Maximum individual capacity of remaining native and all eligible registered tokens. All required candidate reads propagate failures, even after the gas cap is reached. |
| Native | Remaining native capacity only; no registry/token reads, including when funds are insufficient. |
| Token(address) | Strict lazy registry lookup and that token's balance only. Unknown, inactive, unsupported or mode-incompatible selections fail without fallback. |

For each eligible token, raw balance is scaled with its immutable registered
precision (0–18). The shared wide allowance helper caps after division. Applicable
blob fees are reserved from the same payment asset, with wide arithmetic rather
than saturating a scaled product or splitting costs between assets. Dynamic
requests retain their maximum fee cap for affordability while preserving the
normalized effective execution price, including omitted (zero) priority fees.

The estimator's existing binary search, gas caps, and zero-price flow remain in
place. Auto simulations still select native first and then insertion order; the
allowance maximum does **not** pin a simulation to a different token. Payment
switches can make success non-monotonic in the gas limit; no special boundary
search is introduced.

## Simulation and privacy boundaries

Storage/code/block override restrictions remain unchanged. Permitted native
account overrides affect allowance through the same database overlay. Forbidden
storage overrides cannot rewrite the registry or token balances. Private balances
are not returned by public balance endpoints or new accounting responses.
Provider failures propagate as RPC errors. Deterministic payment invalidity uses
the transaction-invalidity channel. Insufficient-funds diagnostics redact amounts
for both direct EVM errors and errors converted by shared block-simulation helpers.
Signed-read outputs and revert data retain the existing response encryption.

`simulateV1` uses a block executor, unlike single-call/estimation execution. Its
request-local `SeismicEvmConfig::snapshot_for_simulation()` opts into the
[Seismic EVM factory's plaintext signed-read mode](https://github.com/SeismicSystems/seismic-evm/blob/seismic/crates/seismic-evm/src/block/mod.rs).
RPC ingress has already authenticated, checked canonical-tip freshness, and
decrypted these requests. The simulation executor must not decrypt plaintext
again or revalidate signed-read expiry against fabricated future block heights.
The live factory never enables this mode. Ordinary encrypted transactions replayed
inside simulations still undergo decryption and execution-height freshness checks.

## Pool admission gas errors

A transaction whose declared gas limit is below the pool's intrinsic gas or
calldata floor still returns RPC code `-32000` and message `intrinsic gas too low`.
Pool admission additionally supplies diagnostic `data`, for example:

```json
{
  "gasLimit": "0x53e8",
  "minimumGasLimit": "0x5528",
  "reason": "calldataFloor"
}
```

The gas values are hex quantities (21,480 supplied, 21,800 required here).
`reason` is `intrinsicGas` or `calldataFloor`, identifying the binding requirement.
The minimum is calculated only from the public submitted transaction, including
its original input bytes and public hardfork rules. Seismic input is still
ciphertext at this stage; these details require no decryption or private-state
reads. Admission rules and peer classification are unchanged.

This data is **pool-only**. General EVM gas-limit errors from execution,
`eth_call`, estimation, and block simulation retain their existing data-less
response; decrypted input costs must never populate the public admission
fields. The legacy fieldless pool error also remains data-less.

## Verification scope

Library tests cover all 19 precisions and both storage modes, strict selections,
read frontiers, required provider failures, wide arithmetic, value funding,
override restrictions, authenticated raw/typed-data decryption, simulated
transaction conversion, privacy-safe errors, and real execution through the
request-local simulated-block executor versus the live/replay paths.

These are targeted library/in-memory execution checks, not real-node wire RPC or
deployment verification. Fresh-chain genesis/bootstrap, coordinated SDK/release
formats, and reth-backed end-to-end coverage remain separate rollout prerequisites.
