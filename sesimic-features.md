This documentation highlights the differences and new features introduced, with a focus on the modifications that make Reth shielded. We recommend familiarizing yourself with the standard Reth documentation alongside this guide.

---

### Table of Contents

1. [Overall Changes](#1-overall-changes)
2. [Shielded Storage](#2-shielded-storage)
    - [2.1 Shielded Storage Flag](#21-shielded-storage-flag)
    - [2.2 State Root Calculation](#22-state-root-calculation)
    - [2.3 `eth_storageAt` RPC Modification](#23-eth_storageat-rpc-modification)
    - [2.4 Storage Hashing Parallelization](#24-storage-hashing-parallelization)
3. [Shielded Transactions](#3-shielded-transactions)
    - [3.1 TEE Client and Arguments](#31-tee-client-and-arguments)
    - [3.2 Transaction Types](#32-transaction-types)
    - [3.3 Transaction Processing](#33-transaction-processing)
    - [3.4 Performance Considerations](#34-performance-considerations)
4. [RPC Interface](#4-rpc-interface)
    - [4.1 Modified Methods](#41-modified-methods)
    - [4.2 New Methods](#42-new-methods)
5. [Security](#5-security)
    - [5.1 TEE Integration](#51-tee-integration)
    - [5.2 Key Management](#52-key-management)
6. [Testing Framework](#6-testing-framework)
    - [6.1 Unit Tests](#61-unit-tests)
    - [6.2 Integration Tests](#62-integration-tests)
7. [Future Development](#7-future-development)
    - [7.1 Planned Features](#71-planned-features)
    - [7.2 Known Limitations](#72-known-limitations)

---

### 1. Overall Changes

We have introduced several changes to make Reth encrypted, enabling shielded storage values and transactions. The key modifications include:

-   **Shielded Storage**: Added an `is_private` flag to all storage values, changing the storage value type from `U256` to `FlaggedStorage`.
-   **Shielded Transaction**: Providing a new transaction type `TxSeismic` that extends the existing transaction and supports shielded input.

---

### 2. Shielded Storage

#### 2.1 Shielded Storage Flag

Previously, storage values were of type `U256`. With the privacy enhancements, we've introduced a new type called `FlaggedStorage`, which includes an `is_private` flag to indicate whether a storage value is confidential.

-   **Implementation**: This change aligns with modifications in `seismic-revm` ([Pull Request #9](https://github.com/SeismicSystems/seismic-revm/pull/9)) and requires the use of REVM inspectors ([Pull Request #1](https://github.com/SeismicSystems/seismic-revm-inspectors/pull/1)).

#### 2.2 State Root Calculation

-   **Modification**: The `is_private` flag is **not** encoded during the state root calculation. This decision is reflected in the code [here](https://github.com/SeismicSystems/seismic-reth/pull/4/commits/5a69f1ea359d3f4e95dd6a825e604548b0e11579#diff-a69280a7601140010b48c98e07c58431efd9e6f45180dcfcd2e0d423e4588a98R162).
-   **Consideration**: We may want to include the `is_private` flag as part of the state since a storage slot can transition from public to private. This is an open point for future development.

#### 2.3 `eth_storageAt` RPC Modification

-   **Behavior**: Modified the `eth_storageAt` RPC method to handle private storage.
    -   If `is_private` is `true`, the RPC call returns `0`.
-   **Rationale**:
    -   **Prevent Information Leakage**: Since storage can transition from private to public, exposing the storage type could leak information through enumeration.
    -   **Potential Misleading Data**: Returning `0` might be misleading if there is a value being stored. Developers should be aware of this behavior.
-   **Code Reference**: [Commit](https://github.com/SeismicSystems/seismic-reth/pull/4/commits/f26de3b8ff74a4b23de0df548c8b629c2479d907)
-   **Impact**: For a complete set of code paths affected, refer to all places where `encode_fixed_size()` is called.

#### 2.4 Storage Hashing Parallelization

-   **Modification**: We include the `is_private` flag along with `addr_key` as the key instead of combining it with the value during parallelization of the `StorageHashingStage`.
-   **Code Reference**: `seismic-reth/crates/stages/stages/src/stages/hashing_storage.rs:106`

---

### 3. Shielded Transactions

Inputs of a shielded transaction is encrypted and can only be decrypted with secret key from TEE. Encryption and decryption logic happens outside of Seismic Reth and inside TEE server. We added modifications to support the communications with TEE and shielded transaction processing.

#### 3.1 TEE Client and Arguments

-   **Addition**: Implemented a Trusted Execution Environment (TEE) client and arguments to interact with a server for decryption and encryption tasks.
-   **Functionality**: Decryption occurs when the EVM initializes with the corresponding transaction, ensuring that the input data remains confidential until execution.

#### 3.2 `TxSeismic` Transaction Type

-   **Definition**: Introduced `TxSeismic`, which defines fields for seismic transactions. In this transaction type, only the `input` field is encrypted.

The `TxSeismic` transaction type contains the following fields:

-   `chain_id`: Chain identifier for replay attack protection (EIP-155)
-   `nonce`: Number of transactions sent by the sender (Tn)
-   `gas_price`: Amount of Wei to be paid per unit of gas for computation costs (Tp). Uses u128 since max Ethereum circulation of ~120M ETH is well within bounds
-   `gas_limit`: Maximum amount of gas allowed for transaction execution (Tg). Must be paid upfront and cannot be increased
-   `to`: 160-bit recipient address for message calls, or empty (∅) for contract creation (Tt)
-   `value`: Amount of Wei to transfer to recipient or endow to new contract (Tv)
-   `encryption_pubkey`: 33-byte public key used to encrypt transaction output
-   `message_version`: Version number of the message format to support EIP-712 `TypedData`
-   `input`: Variable length byte array containing encrypted input

#### 3.3 `ConfigureEvmEnv` and`EthEvmConfig` changes

Extended `ConfigureEvmEnv` trait and `EthEvmConfig` implementation to integrate TEE encryption/decryption capabilities. The `fill_tx_env` method was modified to handle `TxSeismic` transactions by performing TEE-based input decryption prior to EVM execution, enabling shielded transaction processing.

#### 3.4 RPC Method Changes

-   **Modified Methods**

    -   `eth_sendTransaction`
    -   `eth_sendRawTransaction`
    -   `eth_call`
    -   `eth_estimateGas`

    to support shielded transaction

### 4. Support for `seismic-revm`'s `Mercury` specification

#### 4.1 Seismic chain spec

If chain spec is `SEISMIC_MAINNET`(chain id is 5123) or `SEISMIC_DEV` (chain id is 5124), the `Mercury` spec of EVM is used.

### 5. RPC Modifications

#### 5.1 Summary of Modified Endpoints

We have modified several RPC endpoints to support privacy features:

-   **Modified _eth_ RPC Methods**:

    -   **`eth_storageAt`**:
        -   Returns `0` for private storage slots.
        -   **Modification Location**: [Code Reference](https://github.com/SeismicSystems/seismic-reth/pull/4/commits/f26de3b8ff74a4b23de0df548c8b629c2479d907)
    -   **`eth_sendTransaction`**:
        -   Accepts `TxSeismic` transaction type and input encryption
    -   **`eth_sendRawTransaction`**:
        -   Accepts both raw seismic transactions (`Bytes`) and EIP-712 typed data with signatures (`TypedDataRequest`)
    -   **`eth_call`**:
        -   Accepts three types of shielded transaction format:
            -   `TransactionRequest`: Standard transaction call request with additional fields. Since this format of request is unsigned, `msg.sender` is overidden to `None`
            -   `TypedData`: EIP-712 signed typed message with signature
            -   `Bytes`: Raw signed seismic transaction bytes
    -   **`eth_estimateGas`**:
        -   Accepts three types of shielded transaction format:
            -   `TransactionRequest`: Standard transaction call request with additional fields. Since this format of request is unsigned, `msg.sender` is overidden to `None`

-   **SeismicAPI RPC Endpoints**

    -   **`seismic_getTeePublicKey`**:
        -   Returns the network public key for client-side encryption when constructing shielded input

---

### 6. Backup Mechanism

-   **Feature**: Seismic Reth saves the database state every time it reaches a certain canonical block production, controlled by the `DEFAULT_BACKUP_THRESHOLD` parameter.
-   **Consideration**: This feature requires further specification depending on how the consensus layer interacts with Seismic Reth for accurate block counting.
-   **Purpose**: Enables state snapshots at defined intervals, which can be crucial for recovery.

---

#### 7. Performance Testing

We conducted end-to-end tests for the above changes. The performance metrics are as follows:

| **Block Time with HTTP Request** | **0 Calls**   | **1400 Calls** | **5200 Calls** |
| -------------------------------- | ------------- | -------------- | -------------- |
| **1400 Normal Transactions**     | 2.018 seconds | 5.273 seconds  | 10.257 seconds |
| **1400 Encrypted Transactions**  | 6.601 seconds | 11.523 seconds | 21.790 seconds |

-   **Observation**: The HTTP call latency contributes approximately **40%** of the total latency.
-   **Note**: These tests include end-to-end scenarios, demonstrating the overhead introduced by the encryption and decryption processes.

---

### 8. Testing

#### 8.1 Running tests

To ensure the integrity of the shielded enhancements, you can run end-to-end tests using the following command:

```bash
cargo nextest run --workspace
```

#### 8.1 Modifications of existing tests

**Note**: We ignore certain tests by default in `nextest.toml`:

-   `providers::static_file::tests::test_header_truncation`
-   `providers::static_file::tests::test_tx_based_truncation`
-   `eth::core::tests`

For shielded transaction,

For shielded storage, we've modified:

-   `reth-provider writer::tests::write_to_db_storage` to verify that the `is_private` flag is committed to the database from the EVM execution outcome.
-   `reth-trie state::tests::hashed_state_wiped_extension` to ensure that the `is_private` flag is propagated from `hashedStorages` to `postHashedStorages`.

Because we have a decryption call for `TxSeismic` call, `#[tokio::test(flavor = "multi_thread")]` replaces `#[tokio::test]` to provide runtime async support.

#### 8.2 Integration Testing

See the `crates/seismic/node/tests/integration.rs` examples of integration testing using seismic transactions.

#### 8.3 Ethereum Package Testing

We added a `TxSeismic` spammer for Ethereum Package testing. For specific instruction see this [PR](https://github.com/SeismicSystems/seismic-reth/pull/49)

---

### 9. Future Considerations

There are several areas that require attention and potential future development:

1. **Witness Auditing**:

    - **Action**: The `witness()` function needs to be audited to ensure it correctly handles private data.
    - **Importance**: To prevent potential leaks or mishandling of confidential information.

2. **State Root Inclusion of `is_private` Flag**:

    - **Consideration**: Including the `is_private` flag in the state root calculation may be necessary to accurately represent the state where storage slots can transition between public and private.

3. **RPC Method Enhancements**:
    - **Encrypted Events and Data**: Future improvements may include supporting encrypted events, enabling the emission of confidential data without compromising privacy.
