# Seismic pool gas-payment admission and maintenance

`SeismicTransactionValidator` retains Ethereum stateless, nonce, sender-code,
and blob-sidecar validation, while applying registry-backed gas affordability.
The production inner Ethereum validator must have its native-only balance check
**disabled**: the Seismic wrapper is the authoritative affordability gate. This
does not disable balance validation during actual EVM execution.

## One state snapshot

Each admission obtains one `latest()` provider. An `Arc` shares that provider with
`EthTransactionValidator::validate_one_with_state()` and the registry reader.
Native balance, nonce, sender code, registry entries, and token balances therefore
come from the same provider snapshot. No second `latest()` lookup occurs after
Ethereum validation.

`ProviderRegistryStorage` preserves flagged storage. Successfully absent storage
is zero-public; provider errors propagate rather than becoming zero balances.
Registry decoding, full-width mapping keys, precision validation, balance-mode
eligibility, and exact payment selection reuse
[seismic-revm's shared helpers](https://github.com/SeismicSystems/seismic-revm/blob/main/crates/seismic/src/gas_token_registry.rs).

## Exact admission versus approximate pool balance

The signed selector controls exact single-asset affordability:

- `Auto`: native first, then the first eligible registered token in insertion order.
- `Native`: native only, with no token fallback.
- `Token(address)`: exactly that eligible registered token, even when native funds
  or another token could cover the fee.

Standard transactions use Auto. Native currency must fund the **original signed
value**; admission cannot anticipate the execution-only failed-decryption value
exception. One asset must cover the full maximum gas fee, including applicable
blob fees. Fees are computed directly in `U256`, not by subtracting value from
the pool's saturated cached transaction cost. Existing transaction-type and
blob-sidecar restrictions remain unchanged.

After exact selection succeeds, a separate full eligible-token scan produces the
sender-wide promotion scalar:

```text
saturating(native + sum(saturating(raw_balance_i * 10^(18 - decimals_i))))
```

This scalar does not authorize splitting one fee or accurately account for
mixed-asset nonce sequences. Final execution remains the affordability gate.
The complete aggregate scan must propagate all required provider errors, even
when exact native selection or a prior token match needed no later reads.

## Typed, privacy-safe errors

Deterministic registry/payment failures use
`InvalidPoolTransactionError::Other(SeismicPaymentError)`. Trusted in-process
consumers can downcast and inspect `reason()`. `Display`, `Debug`, and the error
source chain do not expose private fee/balance amounts. Do not log the raw reason
or serialize it to an RPC response.

State-dependent failures do not penalize peers. Malformed selectors and
transaction payment overflow remain bad-transaction classifications. Provider
failures instead return `TransactionValidationOutcome::Error`, preserving their
internal-error classification and transaction hash.

## Targeted canonical refresh

`SeismicBalanceHook` reports the same shared registry aggregate as admission.
It does not pin maintenance accounting to the payment asset of one transaction:
pooled senders can mix selectors and tokens across their nonce sequences.

The generic ordered maintenance loop exposes a receipt-independent
`CanonicalStorageChanges` view and a fallible `affected_accounts()` hook:

- Actual registry storage mutations refresh every pooled sender, including
  mutations made through internal calls.
- Token-only changes match full-width `balance_storage_key(sender, root)` keys
  against `pool.unique_senders()`. Privacy-only changes count; read-only cached
  slots do not. Account destruction/deletion refreshes all pooled holders of that
  token, including balances whose keys are absent from the reported storage map.
- Configuration discovery reuses revm's `visit_registered_tokens()` and reads no
  holder balances. Only relevant changed token contracts need holder-key matching;
  there is no persistent registry cache or key index.
- Affected holders are deduplicated with native changed-account records. Added
  holders' native balance/nonce and all registry/token reads use the same new-head
  provider snapshot before existing promotion/demotion machinery is invoked.
- Reorgs inspect both removed and added execution outcomes, then recompute balances
  at the new canonical tip. No transfer events or transaction recipients are needed.

## Maintenance failures and retries

`ChangedAccountsHook` is fallible. Aggregates are staged before changing account
records; only successfully absent slots count as zero. Provider failures and
malformed registry state are typed `SeismicBalanceError` refresh failures, not
per-transaction rejections or reasons to fabricate native-only balances.

Hook failures withhold the entire candidate account batch and requeue its addresses
in the existing dirty-account mechanism. Discovery/snapshot failures conservatively
mark every pooled sender dirty because the affected-holder set may be incomplete.
Failed native reads for added holders are also requeued without fabricated records.
Commit/reorg head and mined-transaction bookkeeping still proceeds. Dirty status
is cleared only after a complete successful refresh.

Asynchronous native-account reloads carry their source block hash. If the pool
head changes before completion, maintenance discards the old records and requeues
the senders rather than combining old native balances/nonces with newer token
state. Current-head reloads augment balances using that same source block hash.
The failed refresh itself neither evicts a transaction nor replaces its cached
account state with a fabricated balance.

## Integration boundary

Registry-backed admission, targeted maintenance, and authenticated RPC allowance
are implemented, but the fresh-chain rollout is **not complete**. Genesis/bootstrap,
SDKs, and real-node integration coverage are still pending. The obsolete hardcoded
`usdc` module and its error-swallowing readers have been removed; consumers use the
shared registry decoding, precision, and eligibility rules.

Replacement and payload-iterator regressions verify that signed selectors remain
in pool storage, consensus/envelope conversions, and local-backup wire bytes.
Marking a transaction invalid during payload selection excludes dependent nonces
without changing or evicting their stored selectors. The sender-wide scalar remains
approximate: final execution must enforce each transaction's chosen payment asset.
Mock-provider pool lifecycle tests are not deployment verification.
