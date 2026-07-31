# TXTYPE e2e test fixtures

`TxTypeProbe.sol` is the source for the `TXTYPE_PROBE_DEPLOY` creation bytecode
embedded in [`../txtype.rs`](../txtype.rs). It is stock Solidity: it reads the
current transaction's EIP-2718 type byte from the `0x6A` tx-type precompile via
`staticcall` — there is no compiler builtin and no `ssolc` change.

## Reproducing the committed bytecode

Compiled with the Seismic Solidity build (`ssolc`, no optimizer, Mercury):

```sh
solc --bin --evm-version mercury TxTypeProbe.sol
```

The **code** portion (everything before the trailing `a264…` CBOR metadata) is
byte-for-byte identical to `TXTYPE_PROBE_DEPLOY`. The metadata suffix encodes
the compiler version/source hash and is not consensus-relevant; the committed
constant was produced with `ssolc 0.8.31-develop.2026.7.20+commit.fd5f389c`.
