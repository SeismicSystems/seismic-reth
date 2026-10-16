# Genesis builder

The `genesis-builder` binary loads an existing genesis JSON and a contract manifest,
fetches runtime artifacts from the manifest's pinned Seismic commit, and adds or
replaces the listed allocations. It does **not** execute constructors or transactions.

```sh
cargo run -p seismic-reth-genesis-builder --bin genesis-builder -- --check
cargo run -p seismic-reth-genesis-builder --bin genesis-builder -- --yes-overwrite
```

Defaults are `crates/seismic/chainspec/res/genesis/manifest.toml` and `dev.json` in
the same directory. `--output` writes elsewhere. `--base-url` overrides the artifact
source for local development; the normal pinned source is reproducible.

An accepted overwrite replaces the **whole account**, including storage, balance
(default zero), and nonce (omitted unless configured). Unlisted addresses are kept;
removing an entry from the manifest does not remove its existing genesis allocation.
`--check` performs replacements only in memory and compares canonical JSON without
writing. Neither mode updates the Rust genesis-hash constant automatically.

## Common validation

GasTokenRegistry uses exactly the same validation path as the other contracts:

- The manifest must contain contracts and pin a full 40-character hexadecimal commit.
- Manifest addresses must have a `0x` prefix; building parses them as 20-byte addresses,
  padding short spellings as needed.
- Artifacts must provide `deployedBytecode.object`, which must decode as hex bytes.
- `--check` compares the generated canonical JSON against the output file.

There are no contract-specific runtime-hash, owner, token-count, or storage-layout
checks. Storage is copied from the manifest rather than interpreted by the builder.
Reproducibility and drift checking do not prove semantic correctness of a manifest.
There are also no new node-startup checks. Initial owner/count configuration and
post-genesis token funding/registration remain the responsibility of the manifest,
operators, and application tests. The builder does not mint tokens or call `addToken`.

## Verification

```sh
CARGO_BUILD_JOBS=1 cargo test -p reth-seismic-genesis-builder -- --test-threads=1
CARGO_BUILD_JOBS=1 cargo test -p reth-seismic-chainspec --lib -- --test-threads=1
```

The manifest tests verify that GasTokenRegistry and generic contract entries follow
the same commit/address validation. Chainspec tests check committed dev canonical
serialization and genesis header hashes. Keep Cargo checks sequential when resource limited.
