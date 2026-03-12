# Address Screening Module

Operator-enforced compliance screening for Seismic validators via integration with [CipherOwl's ECSD](https://cipherowl.ai/) (Ethereum Compliance Screening Daemon).

## Overview

This module provides **opt-in** address screening at transaction pool admission. It extracts addresses from transactions and queries an external ECSD sidecar to check if any addresses are flagged for compliance concerns. This is an **operator policy layer** separate from the protocol's consensus rules.

### Key Design Principles

1. **Separation of Concerns**: Screening is a separate `ScreeningTransactionValidator` wrapper, NOT part of `SeismicTransactionValidator` (which handles protocol invariants)
2. **Opt-in**: Disabled by default, enabled via `--screening.enable` CLI flag
3. **Type Transparency**: Uses `Either<A, B>` to maintain the same pool type whether screening is enabled or not
4. **Fail-Safe Modes**: Configurable behavior when ECSD is unreachable (fail-open or fail-closed)
5. **Observability**: Prometheus metrics for latency, throughput, and error rates

## Architecture

```
Transaction → TransactionValidationTaskExecutor → Either<
    SeismicTransactionValidator,                    // No screening
    ScreeningTransactionValidator<                  // With screening
        SeismicTransactionValidator
    >
>
```

### Components

#### 1. **Calldata Address Extraction** ([`calldata.rs`](calldata.rs))

Extracts Ethereum addresses from transaction calldata for common token standards:

- **Transaction-level addresses**: sender, recipient (`tx.to()`), EIP-7702 authorizations, access lists
- **ERC-20**: `transfer(address,uint256)`, `approve(address,uint256)`, `transferFrom(address,address,uint256)`
- **ERC-721**: `safeTransferFrom(address,address,uint256)`, `safeTransferFrom(address,address,uint256,bytes)`
- **ERC-1155**: `safeTransferFrom(address,address,uint256,uint256,bytes)`, `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)`

**Performance**: ~18ns per extraction (see [benchmarks](../../benches/README.md))

#### 2. **ECSD gRPC Client** ([`client.rs`](client.rs))

Persistent HTTP/2 connection to ECSD sidecar using tonic/prost:

- **Lazy Connection**: Uses `connect_lazy()` for deferred connection (node starts even if ECSD is down)
- **Configurable Timeout**: Default 100ms (configurable via CLI)
- **Fail Modes**:
  - `Open`: Allow transaction if ECSD is unreachable (default)
  - `Closed`: Reject transaction if ECSD is unreachable
- **gRPC Method**: `BatchCheckAddresses` from `ai.cipherowl.ecsd.v1.ECSd` service

**Performance**: ~470µs per request with real ECSD (see [benchmarks](../../benches/README.md))

#### 3. **Screening Metrics** ([`metrics.rs`](metrics.rs))

Prometheus metrics under `reth.txpool.screening.*`:

| Metric | Type | Description |
|--------|------|-------------|
| `screening_request_duration` | Histogram | End-to-end ECSD request latency |
| `address_extraction_duration` | Histogram | Time to extract addresses from calldata |
| `addresses_per_request` | Histogram | Distribution of addresses per transaction |
| `screened_transactions` | Counter | Total transactions screened |
| `flagged_transactions` | Counter | Transactions rejected due to flagged addresses |
| `screening_errors` | Counter | ECSD request failures |

#### 4. **Transaction Validator Wrapper** ([`validator.rs`](validator.rs))

Implements `TransactionValidator` trait:

```rust
pub struct ScreeningTransactionValidator<V> {
    inner: V,                          // SeismicTransactionValidator
    screening_client: ScreeningClient,
    metrics: ScreeningMetrics,
}
```

**Workflow**:
1. Extract addresses from transaction (sender, recipient, calldata, access list, authorizations)
2. Call `screening_client.screen_addresses(addrs).await`
3. If any addresses are flagged → return `InvalidTransactionError::SeismicTx("address screening failed")`
4. Otherwise → delegate to `inner.validate_transaction()`
5. Record metrics for observability

## Usage

### CLI Configuration

Enable screening on validator startup:

```bash
seismic-reth node \
  --screening.enable \
  --screening.endpoint http://127.0.0.1:9090 \
  --screening.timeout-ms 100 \
  --screening.fail-mode open
```

**CLI Flags**:
- `--screening.enable`: Enable address screening (default: `false`)
- `--screening.endpoint`: ECSD gRPC endpoint (default: `http://127.0.0.1:9090`)
- `--screening.timeout-ms`: Request timeout in milliseconds (default: `100`)
- `--screening.fail-mode`: Behavior when ECSD is unreachable - `open` or `closed` (default: `open`)

### Running ECSD Sidecar

#### Option 1: Docker (Recommended)

```bash
# Pull latest ECSD image
docker pull cipherowl/ecsd:latest

# Run with default configuration
docker run -p 9090:9090 cipherowl/ecsd:latest
```

#### Option 2: Build from Source

See [CipherOwl addressdb repository](https://github.com/cipherowl-ai/addressdb) for build instructions.

### Programmatic Usage

```rust
use reth_seismic_txpool::screening::{
    ScreeningClient, ScreeningClientBuilder, ScreeningFailMode,
};

// Create screening client
let client = ScreeningClientBuilder::new("http://127.0.0.1:9090")
    .timeout(Duration::from_millis(100))
    .fail_mode(ScreeningFailMode::Open)
    .build()?;

// Screen addresses
let addresses = vec![
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
    "0x1111111111111111111111111111111111111111".to_string(),
];

match client.screen_addresses(addresses).await {
    Ok(flagged) if flagged.is_empty() => println!("All addresses clean"),
    Ok(flagged) => println!("Flagged addresses: {:?}", flagged),
    Err(e) => eprintln!("Screening error: {}", e),
}
```

## Performance

Benchmarks run against real ECSD Docker container (see [`benches/README.md`](../../benches/README.md) for details):

| Metric | Value | Notes |
|--------|-------|-------|
| **Calldata extraction** | ~18ns | Negligible CPU overhead |
| **ECSD gRPC latency** | ~470µs | Per transaction, includes network + Bloom filter lookup |
| **Throughput** | ~2,100 tx/sec | Sequential screening, single stream |
| **Scalability** | Linear | ~2µs per additional address |

**Conclusion**: Screening adds **<1ms overhead per transaction** with generous 100ms timeout providing 200x safety margin.

## Error Handling

### Fail Modes

1. **Fail-Open** (default, `--screening.fail-mode open`):
   - If ECSD is unreachable → **allow transaction** and log error
   - If ECSD times out → **allow transaction** and increment `screening_errors`
   - If gRPC error → **allow transaction** and log error
   - Use when uptime is more critical than compliance

2. **Fail-Closed** (`--screening.fail-mode closed`):
   - If ECSD is unreachable → **reject transaction**
   - If ECSD times out → **reject transaction**
   - If gRPC error → **reject transaction**
   - Use when compliance is more critical than uptime

### Error Types

| Error | Fail-Open Behavior | Fail-Closed Behavior |
|-------|-------------------|---------------------|
| ECSD unreachable | Allow | Reject |
| Request timeout | Allow | Reject |
| gRPC transport error | Allow | Reject |
| Invalid gRPC response | Allow | Reject |
| Flagged address found | **Always Reject** | **Always Reject** |

## Testing

### Unit Tests

```bash
# Run all screening tests
cargo test -p reth-seismic-txpool screening

# Run specific test modules
cargo test -p reth-seismic-txpool screening::calldata
cargo test -p reth-seismic-txpool screening::client
```

**Test Coverage**:
- ✅ Calldata extraction for all token standards (ERC-20, ERC-721, ERC-1155)
- ✅ Edge cases (empty calldata, truncated data, malformed addresses)
- ✅ Client builder with various configurations
- ✅ Fail-open and fail-closed behavior with unreachable endpoint

### Benchmarks

```bash
# Run all screening benchmarks (requires ECSD Docker running)
cargo bench -p reth-seismic-txpool --bench screening

# Run specific benchmark groups
cargo bench -p reth-seismic-txpool --bench screening -- "latency"
cargo bench -p reth-seismic-txpool --bench screening -- "throughput"
```

See [`benches/README.md`](../../benches/README.md) for setup instructions and detailed results.

## Monitoring

### Prometheus Metrics

Access metrics at `http://localhost:9001/metrics` (default reth metrics endpoint):

```promql
# Success rate
rate(reth_txpool_screening_screened_transactions_total[5m]) /
rate(reth_txpool_screening_flagged_transactions_total[5m])

# P95 latency
histogram_quantile(0.95,
  rate(reth_txpool_screening_screening_request_duration_bucket[5m])
)

# Error rate
rate(reth_txpool_screening_screening_errors_total[5m])

# Addresses per transaction distribution
histogram_quantile(0.95,
  rate(reth_txpool_screening_addresses_per_request_bucket[5m])
)
```

### Logging

Screening events are logged at appropriate levels:

- `INFO`: ECSD connection established, configuration
- `WARN`: Screening errors in fail-open mode
- `ERROR`: Screening failures in fail-closed mode
- `DEBUG`: Individual transaction screening results

## FAQ

### Q: Does screening affect consensus?

**A:** No. Screening is an **operator policy** enforced at the transaction pool level, not a consensus rule. Different validators can have different screening configurations. Transactions rejected by screening can still be included by other validators.

### Q: What happens if ECSD goes down?

**A:** Depends on fail mode:
- **Fail-open** (default): Transactions are allowed, errors are logged and counted in metrics
- **Fail-closed**: Transactions are rejected, protecting compliance at the cost of availability

### Q: Can I screen only certain transaction types?

**A:** Currently no. Screening applies to all transactions entering the pool. If you need selective screening, consider running multiple nodes with different configurations.

### Q: How much does screening cost in terms of performance?

**A:** ~470µs per transaction with real ECSD (~0.05% of typical block time). The 100ms timeout provides 200x safety margin.

### Q: Can I use a remote ECSD instance?

**A:** Yes, specify the endpoint via `--screening.endpoint https://remote-ecsd.example.com:9090`. Be mindful of network latency and consider increasing the timeout accordingly.

### Q: What addresses are extracted for screening?

**A:**
- Transaction sender (always)
- Transaction recipient (`tx.to()`) if present
- EIP-7702 authorization addresses
- Access list addresses
- ERC-20/721/1155 addresses from calldata (if recognized selector)

### Q: Are there privacy concerns with sending addresses to ECSD?

**A:** ECSD uses Bloom filters for privacy-preserving screening. The service doesn't learn the full set of flagged addresses, only checks membership. However, the ECSD operator can see which addresses you're screening. For maximum privacy, run ECSD locally.

## Security Considerations

1. **Network Security**: ECSD endpoint should be on a trusted network. Consider using TLS for remote connections.
2. **Fail Mode Selection**: Choose based on your threat model (availability vs. compliance)
3. **Timeout Configuration**: Too short → spurious rejections; too long → DoS risk
4. **Local Deployment**: Run ECSD as a sidecar on the same machine for lowest latency and highest trust

## Contributing

When adding new token standards or address extraction logic:

1. Update [`calldata.rs`](calldata.rs) with new selectors
2. Add comprehensive tests for the new standard
3. Document the selector in this README
4. Add benchmark cases if applicable

## References

- [ECSD Documentation](https://github.com/cipherowl-ai/addressdb)
- [EIP-7702: Set EOA account code](https://eips.ethereum.org/EIPS/eip-7702)
- [ERC-20: Token Standard](https://eips.ethereum.org/EIPS/eip-20)
- [ERC-721: Non-Fungible Token Standard](https://eips.ethereum.org/EIPS/eip-721)
- [ERC-1155: Multi Token Standard](https://eips.ethereum.org/EIPS/eip-1155)
