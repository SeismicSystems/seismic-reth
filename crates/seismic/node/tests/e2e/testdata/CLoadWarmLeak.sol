// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Reads slot 0 of the caller's storage as a *public*
/// `mapping(uint256 => uint256)`. `CLoadWarmLeak` delegatecalls this so the same
/// storage slot is reinterpreted under a public type, yielding a plain-Solidity
/// `sload` of an arbitrary slot without inline assembly.
contract CLoadWarmPublicReader {
    mapping(uint256 => uint256) private values;

    function read(uint256 key) external view returns (uint256) {
        return values[key];
    }
}

/// @notice Regression fixture for the CLOAD access-set warm-up invariant, using no
/// inline assembly.
///
/// `probe(reader, k)` performs a confidential read of slot `keccak(k, 0)` via the
/// shielded mapping (`values[k]`, i.e. `cload`), then a standard `sload` of the
/// fixed slot `keccak(5, 0)` by delegatecalling `CLoadWarmPublicReader.read(5)`,
/// which reinterprets slot 0 as its public mapping.
///
/// If `cload` leaks the EIP-2929 access-set bit, `probe(reader, 5)` is 2000 gas
/// cheaper than `probe(reader, 6)`: only `k == 5` makes the confidential slot
/// coincide with the probed slot, so only then does the standard `sload` observe a
/// warm slot. An integration test asserts the combined cost is independent of `k`.
///
/// The `cload` result is *used* (`v = uint256(c) + ...`) on purpose. If it were
/// discarded the optimizer would treat the confidential read as dead and remove it,
/// and the leak would never reach the bytecode.
///
/// Bytecode embedded in `integration.rs` was produced with:
///   ssolc --bin --optimize testdata/CLoadWarmLeak.sol
contract CLoadWarmLeak {
    /// @dev Slot 0. Read as `cload` because the value type is shielded.
    mapping(uint256 => suint256) private values;

    function probe(address reader, uint256 k) external returns (uint256 v) {
        // Confidential read of keccak(k, 0).
        suint256 c = values[k];

        // Standard read of keccak(5, 0), under a public type view of the same slot 0.
        // Slot 0 is left unwritten, so it is public and the `sload` returns zero
        // rather than reverting.
        (bool ok, bytes memory data) =
            reader.delegatecall(abi.encodeWithSignature("read(uint256)", uint256(5)));
        require(ok, "reader delegatecall failed");

        v = uint256(c) + abi.decode(data, (uint256));
    }
}
