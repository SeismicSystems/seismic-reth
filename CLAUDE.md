# Seismic Reth

Fork of [Reth](https://github.com/paradigmxyz/reth) (Ethereum execution client in Rust) that adds **shielded storage and transactions** to the EVM. Seismic Reth enables smart contracts to handle sensitive data privately on-chain via encrypted calldata and confidential storage slots, running inside a Trusted Execution Environment (TEE). Upstream is tracked from `paradigmxyz/reth`.

## What This Does

Standard EVM storage is publicly readable. Seismic extends Reth with:

- **Shielded Storage**: Storage values use `FlaggedStorage` (wraps `U256` + `is_private` flag). Private slots use `CSTORE`/`CLOAD` opcodes and return `0` from `eth_getStorageAt`.
- **Shielded Transactions**: A new `TxSeismic` transaction type with encrypted `input` field. Encryption uses ECDH between client ephemeral keys and the network's TEE public key. Decryption happens inside the TEE before EVM execution.
- **Seismic Chain Specs**: `SEISMIC_MAINNET` (chain ID 5123) and `SEISMIC_DEV` (chain ID 5124) use the `Mercury` EVM spec from `seismic-revm`.
- **Custom RPC**: Modified `eth_sendRawTransaction`, `eth_call`, `eth_estimateGas` for shielded tx support. Added `seismic_getTeePublicKey` endpoint.

## Build

Rust workspace with ~150 crates. MSRV is **1.88.0**. Requires **stable** + **nightly** (for `rustfmt`). Output binaries: `seismic-reth` and `genesis-builder`.

### macOS (arm64/x86_64)

```bash
# Prerequisites: Rust stable >= 1.88, Rust nightly, cargo-nextest
rustup toolchain install stable nightly
cargo install cargo-nextest --locked

# Build (debug)
cargo build --bin seismic-reth
cargo build --bin genesis-builder

# Build (release, with jemalloc + asm-keccak)
cargo build --bin seismic-reth --release --features "jemalloc asm-keccak"
```

### Linux (Ubuntu)

```bash
# System dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev libclang-dev

# Prerequisites: Rust stable >= 1.88, Rust nightly, cargo-nextest
rustup toolchain install stable nightly
cargo install cargo-nextest --locked

# Build (debug)
cargo build --bin seismic-reth
cargo build --bin genesis-builder

# Build (release, with jemalloc + asm-keccak)
cargo build --bin seismic-reth --release --features "jemalloc asm-keccak"
```

### Verify

```bash
target/debug/seismic-reth --version
# Expected: reth-seismic-cli Version: 1.7.0
# Commit SHA: ...
# Build Features: jemalloc
```

## Test

Tests use `cargo-nextest`. Some tests are filtered out by default in `.config/nextest.toml`.

### Unit tests (~2012 tests)

```bash
cargo nextest run --workspace -E '!kind(test)' --no-fail-fast
```

### Integration tests (~318 tests)

```bash
cargo nextest run --workspace -E 'kind(test)' --no-fail-fast
```

### All tests (unit + integration)

```bash
cargo nextest run --workspace --no-fail-fast
```

### Test a specific crate

```bash
cargo nextest run -p reth-seismic-node
cargo nextest run -p reth-seismic-evm
```

### Ethereum Foundation tests (requires download)

```bash
make ef-tests
```

### Viem integration tests (requires bun)

```bash
bun install
bun viem:test
```

## Lint

### Format (nightly rustfmt required)

```bash
cargo +nightly fmt --all          # format
cargo +nightly fmt --all --check  # check only
```

### Clippy — seismic crates (matches CI)

```bash
cargo clippy \
  -p reth-seismic-primitives -p reth-seismic-chainspec -p reth-seismic-evm \
  -p reth-seismic-payload-builder -p reth-seismic-node -p reth-seismic-rpc \
  -p reth-seismic-cli -p reth-seismic-txpool -p reth-seismic-forks -p seismic-reth \
  --lib --tests --no-deps \
  -- -D warnings \
  -W clippy::unwrap_used -W clippy::expect_used -W clippy::indexing_slicing \
  -W clippy::panic -W clippy::unreachable -W clippy::todo
```

### Warnings check (matches CI)

```bash
RUSTFLAGS="-D warnings" cargo check
```

### TOML formatting (if changing Cargo.toml files)

```bash
# Requires: cargo install --locked dprint
dprint fmt
```

## Project Layout

```
bin/
  seismic-reth/          Main binary — Seismic node entry point
  genesis-builder/       Genesis block builder tool
  reth/                  Upstream reth binary (not default-built)
crates/
  seismic/               ★ Seismic-specific crates
    chainspec/           Seismic chain specs (mainnet 5123, dev 5124)
    cli/                 Seismic CLI extensions
    evm/                 Seismic EVM config (TxSeismic decryption, Mercury spec)
    hardforks/           Seismic hardfork definitions
    node/                Seismic node builder + integration tests
    payload/             Seismic payload builder (shielded tx handling)
    primitives/          TxSeismic type, FlaggedStorage, shielded types
    reth/                Re-exports of seismic crates
    rpc/                 Seismic RPC extensions (seismic_getTeePublicKey, etc.)
    txpool/              Seismic transaction pool (TxSeismic validation)
  consensus/             Block validation (Ethereum consensus rules)
  engine/                Consensus engine (Engine API: newPayload, forkchoiceUpdated)
  ethereum/              Ethereum-specific: hardforks, EVM, node, primitives, payload
  evm/                   Generic EVM execution traits and types
  net/                   P2P networking (discv4/v5, eth-wire, ecies, downloaders)
  node/                  Node builder, core config, events, metrics
  rpc/                   JSON-RPC server, API definitions, engine API
  stages/                Staged sync pipeline
  storage/               MDBX database, codecs, static files, nippy-jar
  trie/                  Merkle Patricia Trie (parallel state root computation)
  genesis-builder/       Genesis builder library
testing/
  ef-tests/              Ethereum Foundation test runner
  viem-tests/            Viem integration tests (TypeScript/bun)
```

## Key Seismic Modifications

Shielded features are layered on top of upstream Reth:

- **TxSeismic type**: `crates/seismic/primitives/` — new transaction type with encrypted `input`, `encryption_pubkey`, `message_version`
- **FlaggedStorage**: `seismic-revm` (external) — storage values carry `is_private` flag; `CSTORE`/`CLOAD` opcodes
- **EVM config**: `crates/seismic/evm/` — decrypts `TxSeismic` input before execution via TEE cryptography server
- **Chain specs**: `crates/seismic/chainspec/` — SEISMIC_MAINNET (5123), SEISMIC_DEV (5124) with Mercury spec
- **RPC extensions**: `crates/seismic/rpc/` — modified eth_call/sendRawTransaction, added seismic_getTeePublicKey
- **State root**: `is_private` flag excluded from state root calculation (storage hashing includes it as key metadata)

## Dependencies (Seismic forks)

All patched via `[patch.crates-io]` in root `Cargo.toml`:

| Dependency                  | Seismic Fork                             |
| --------------------------- | ---------------------------------------- |
| `revm` (+ sub-crates)       | `SeismicSystems/seismic-revm`            |
| `alloy-primitives` (+ core) | `SeismicSystems/seismic-alloy-core`      |
| `alloy-trie`                | `SeismicSystems/seismic-trie`            |
| `alloy-evm`                 | `SeismicSystems/seismic-evm`             |
| `revm-inspectors`           | `SeismicSystems/seismic-revm-inspectors` |
| `seismic-alloy-*`           | `SeismicSystems/seismic-alloy`           |
| `seismic-enclave`           | `SeismicSystems/enclave`                 |

## Code Style

- **Nightly rustfmt** with config in `rustfmt.toml` (reorder imports, crate-level granularity, max heuristics, trailing comma vertical)
- **Clippy**: Seismic crates enforce `-W clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `unreachable`, `todo`
- **Logging**: Use `tracing` crate — `tracing::debug!(target: "reth::component", ?value, "description");`
- **File I/O**: Use `reth_fs_util` instead of `std::fs`
- **Async tests**: Use `#[tokio::test(flavor = "multi_thread")]` (required for shielded tx tests that call decryption)
- **Commit messages**: Conventional format (`feat:`, `fix:`, `chore:`, `docs:`)

## CI

GitHub Actions (`.github/workflows/seismic.yml`):

| Job                | What it does                                             |
| ------------------ | -------------------------------------------------------- |
| `rustfmt`          | `cargo fmt --all --check` (nightly)                      |
| `warnings`         | `RUSTFLAGS="-D warnings" cargo check`                    |
| `clippy`           | Clippy on all seismic crates with strict lints           |
| `unit-test`        | `cargo nextest run --workspace -E '!kind(test)'`         |
| `integration-test` | `cargo nextest run --workspace -E 'kind(test)'`          |
| `viem`             | Builds seismic-reth, runs viem integration tests via bun |

## Branches

- `seismic` — main branch (PR target)
- Upstream tracking via periodic merges from `paradigmxyz/reth`

## Important Rules

- **Never modify** files in `crates/storage/libmdbx-rs/mdbx-sys/libmdbx/` — vendored third-party code
- **Nextest filters**: `.config/nextest.toml` excludes flaky tests (`test_header_truncation`, `test_tx_based_truncation`, `eth::core::tests`)
- **Default members**: Only `bin/seismic-reth` and `bin/genesis-builder` build by default (`cargo build` without `--workspace`)
- **Optimism crates**: Commented out of workspace — do not re-enable
- **Seismic-specific crate naming**: All seismic crates use `reth-seismic-*` prefix

## Troubleshooting

| Problem                                 | Fix                                                                                                                           |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `cargo build` compiles all crates       | Default members are `seismic-reth` and `genesis-builder`. Use `cargo build --bin seismic-reth` to build only the main binary. |
| `cargo fmt` uses wrong edition features | Must use nightly: `cargo +nightly fmt --all`                                                                                  |
| `cargo-nextest` not found               | `cargo install cargo-nextest --locked`                                                                                        |
| libmdbx build fails on Linux            | Install `libclang-dev`: `sudo apt-get install libclang-dev`                                                                   |
| Tests filtered/skipped unexpectedly     | Check `.config/nextest.toml` for default filter exclusions                                                                    |
| Clippy warnings in seismic crates       | CI uses strict lints (`unwrap_used`, `expect_used`, etc.) — use `.ok()`, `get()`, `if let` instead                            |
| Integration tests need async runtime    | Use `#[tokio::test(flavor = "multi_thread")]` not `#[tokio::test]` for tests involving TxSeismic                              |
| TOML format check fails                 | Install and run `dprint fmt` (requires `cargo install --locked dprint`)                                                       |
| Dependency changes in Cargo.toml        | Run `dprint fmt` before committing to fix TOML formatting                                                                     |
