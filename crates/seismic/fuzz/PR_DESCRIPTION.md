This PR adds the following:

## Adversarial fuzzing framework for seismic-reth

A proptest-based fuzzing framework (`reth-seismic-fuzz`) that stress-tests all seismic-specific code paths for panics. Any panic in production code is treated as a security bug since it can crash the node.

### What's tested

- **Precompile crash-freedom**: All 5 stateless seismic precompiles (AES-GCM encrypt/decrypt, ECDH, HKDF, secp256k1-sign) fuzzed with arbitrary bytes and gas limits, including boundary-length inputs near each precompile's expected input size.

- **EVM execution crash-freedom**: Full `SeismicEvm.transact()` with arbitrary transactions across all tx types (Legacy, EIP-2930, EIP-1559, Seismic 0x4A) and contract deployments.

- **Flagged storage crash-freedom**: Dynamically-constructed bytecode with SLOAD, CLOAD (0xB0), and CSTORE (0xB1) opcodes on arbitrary storage slots, exercising the privacy boundary enforcement between public and private storage.

- **Differential correctness**: Same non-seismic transaction executed on both SeismicEvm and plain revm, comparing success/failure outcome, gas usage, output bytes, and error reasons. Any divergence is a regression.

- **Transaction encoding roundtrips**: EIP-2718 and Compact codec encode/decode roundtrips, plus raw arbitrary bytes fed into decoders to verify crash-freedom on the P2P attack surface.

### Bug fix: `Decompress` panic on corrupt database entries

The zstd decompressor in `ReusableDecompressor::decompress` (`zstd-compressors/src/lib.rs`) panics via `assert!` when it encounters malformed data (e.g. "Unknown frame descriptor", "Dictionary mismatch"). This panic is reachable through any DB read that touches a corrupt entry — including P2P request handlers serving data to remote peers.

This is a known issue in upstream reth. A user reported it in [paradigmxyz/reth#16052](https://github.com/paradigmxyz/reth/issues/16052): their node ran for 6 hours with a corrupt snapshot, surviving its own sync loop (which handled MDBX-level corruption gracefully), until a random peer requested data from the corrupt region. The P2P handler hit the zstd assert and the entire node crashed.

**Fix**: The `Decompress` trait implementations in `db-api/src/models/mod.rs` (the bridge between `Compact::from_compact` and the DB read path) now wrap `from_compact` in `catch_unwind`. If the zstd decompressor (or any other `from_compact` code) panics, it's caught and converted to `DatabaseError::Decode`. The existing error handling at every layer above — staged sync pipeline, P2P request handler, RPC — handles `DatabaseError` gracefully. The node stays up.

**Validation**: The `db_corruption.rs` integration test writes a valid transaction to MDBX, overwrites it with corrupt bytes (zstd flag set, garbage payload) via `RawTable`, then reads it back through the production code path (`tx.get::<Transactions>()` → `decode_one` → `Decompress::decompress`). It asserts that:
1. The read returns `Err(DatabaseError::Decode)` instead of panicking
2. The zstd decompressor panic actually fired internally (captured via `set_hook`)
