// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// Minimal PoC for the "block overrides bypass private-read guards" finding.
///
/// `secret` lives in shielded (`suint`) storage, so the compiler emits CSTORE on
/// write and CLOAD on read. The only thing protecting the read is a block-context
/// guard (`block.timestamp`), which an unsigned eth_call can satisfy via
/// `blockOverrides` — reaching the private CLOAD and returning it as plaintext.
contract TimeLockedSecret {
    suint256 private secret;
    // Far-future reveal time in SECONDS (~year 2096). Note: Seismic stores block
    // time in milliseconds and the EVM TIMESTAMP opcode exposes time/1000, so a
    // blockOverrides.time of 0x7fffffffffffffff (ms) lands as ~9.2e15s in the EVM —
    // well above this guard, and far above the real chain time (~1.7e9s).
    uint256 private constant REVEAL_TIME = 4_000_000_000;

    constructor() {
        secret = suint256(42); // CSTORE -> private slot 0
    }

    function getSecret() external view returns (uint256) {
        require(block.timestamp >= REVEAL_TIME, "locked");
        return uint256(secret); // CLOAD -> returned as plaintext on the call path
    }
}
