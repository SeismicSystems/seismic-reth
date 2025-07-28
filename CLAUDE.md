# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Seismic Reth is an encrypted blockchain client that extends [Reth](https://github.com/paradigmxyz/reth) with shielded transaction and storage capabilities. It enables users to confidentially interact with smart contracts and transactions on the Seismic network while maintaining compatibility with existing Ethereum infrastructure. Seismic Reth runs in a Trusted Execution Environment (TEE) for secure communication.

## Common Development Commands

### Building and Testing
```bash
# Build the seismic-reth binary (preferred over regular reth)
cargo build --bin seismic-reth --features "jemalloc asm-keccak min-debug-logs" --profile release

# Build for development/debugging  
cargo build --bin seismic-reth --features "jemalloc asm-keccak min-debug-logs"

# Run all tests (uses nextest configuration from .config/nextest.toml)
cargo nextest run --workspace

# Run seismic-specific tests only
make test-seismic-reth

# Run with Ethereum Foundation tests (requires setup)
cargo nextest run -p ef-tests --features ef-tests

# Run with Geth compatibility tests
cargo nextest run --workspace --features geth-tests
```

### Code Quality and Linting
```bash
# Format code
make fmt
# Or directly: cargo +nightly fmt

# Run clippy lints
make clippy
# Or directly: cargo +nightly clippy --workspace --lib --examples --tests --benches --all-features -- -D warnings

# Run all lints (format, clippy, codespell, toml formatting)
make lint

# Fix linting issues automatically
make fix-lint
```

### Development Builds
```bash
# Install seismic-reth locally to ~/.cargo/bin
make install

# Build with profiling symbols (for performance analysis)
make profiling

# Build with maximum performance optimizations
make maxperf
```

### Documentation
```bash
# Generate and open documentation
make rustdocs

# Update CLI documentation in book
make update-book-cli
```

## Architecture Overview

### Core Components

**Seismic Extensions (`crates/seismic/`)**:
- **`seismic/node/`**: Main node implementation with TEE integration
- **`seismic/evm/`**: EVM configuration for encrypted execution 
- **`seismic/rpc/`**: RPC API extensions for shielded transactions
- **`seismic/txpool/`**: Transaction pool handling for encrypted transactions
- **`seismic/primitives/`**: Core data types including `TxSeismic` transaction type

**Standard Reth Components**:
- **`node/`**: Node builder and configuration
- **`net/`**: P2P networking layer
- **`engine/`**: Consensus engine and block production
- **`storage/`**: Database and state management  
- **`rpc/`**: JSON-RPC API implementation
- **`evm/`**: Ethereum Virtual Machine execution

### Shielded Features

**Shielded Storage**: 
- Storage values use `FlaggedStorage` type with `is_private` flag instead of plain `U256`
- Private storage returns `0` via `eth_storageAt` RPC to prevent information leakage
- State root calculation excludes the `is_private` flag (see `seismic-features.md`)

**Shielded Transactions**:
- New `TxSeismic` transaction type with encrypted `input` field
- Client-side encryption using ephemeral keys and ECDH key exchange
- Server-side decryption via external cryptography service (TEE)
- Modified RPC methods: `eth_sendTransaction`, `eth_sendRawTransaction`, `eth_call`, `eth_estimateGas`

**TEE Integration**:
- Encrypted execution environment via `seismic-enclave` crate
- Mock enclave server for development (`mock_server` config option)
- Genesis boot process for production enclaves

### Main Entry Points

- **`bin/seismic-reth/src/main.rs`**: Primary binary entry point
- **`crates/seismic/node/src/node.rs`**: Seismic node implementation
- **`crates/seismic/rpc/src/eth/api.rs`**: Extended RPC API handlers

## Testing Notes

### Test Configuration
- Nextest configuration in `.config/nextest.toml` excludes certain flaky tests by default
- Multi-threaded test runtime required for `TxSeismic` decryption: use `#[tokio::test(flavor = "multi_thread")]`

### Integration Tests
- End-to-end testing examples in `crates/seismic/node/tests/integration.rs`
- Ethereum Package testing with `TxSeismic` spammer support
- Viem compatibility tests in `testing/viem-tests/`

### Test Categories
```bash
# Unit tests only
make test-unit

# Seismic-specific tests
make test-seismic-reth

# Full test suite including docs
make test
```

## Important Implementation Details

### Encryption Flow
1. **Client**: Generate ephemeral keypair, encrypt calldata with ECDH shared secret
2. **Network**: Decrypt using network private key + ephemeral public key  
3. **EVM**: Execute with decrypted input
4. **Response**: Encrypt output for `eth_call` responses

### Configuration
- Chain ID 5123 (SEISMIC_MAINNET) or 5124 (SEISMIC_DEV) enables Mercury EVM spec
- Enclave server configuration via `enclave.enclave_server_addr` and `enclave.enclave_server_port`
- Mock server mode for development testing

### Modified RPC Endpoints
- **seismic_getTeePublicKey**: Returns network public key for client encryption
- **eth_storageAt**: Returns 0 for private storage slots
- **eth_sendRawTransaction**: Accepts both raw bytes and EIP-712 typed data
- **eth_call**: Supports encrypted transactions with output encryption

## Development Workflow

1. **Setup**: Ensure Rust 1.86+ and optionally Geth for full testing
2. **Build**: Use seismic-reth binary, not standard reth
3. **Test**: Run `cargo nextest run --workspace` for full test suite
4. **Lint**: Always run `make lint` before committing
5. **Performance**: Use `make profiling` for performance analysis builds

Refer to `seismic-features.md` for detailed information about shielded features and implementation specifics.