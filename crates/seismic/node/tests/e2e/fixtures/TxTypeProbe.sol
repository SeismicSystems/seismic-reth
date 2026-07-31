// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Source for the `TXTYPE_PROBE_DEPLOY` bytecode used by the e2e tests in
// `../txtype.rs`. Stock Solidity — reads the EIP-2718 tx type from the 0x6A
// tx-type precompile via `staticcall`, no compiler builtin. See `README.md`
// for the exact compile command that reproduces the committed bytecode.
contract TxTypeProbe {
    address constant TX_TYPE = address(0x6A);

    function _txType() private view returns (uint256 t) {
        (bool ok, bytes memory ret) = TX_TYPE.staticcall("");
        require(ok && ret.length == 32, "TX_INFO");
        t = abi.decode(ret, (uint256));
    }

    // isSeismic() [selector 02ce8088]: txType() == 0x4A as an abi bool.
    function isSeismic() external view returns (bool) {
        return _txType() == 0x4A;
    }

    // requireSeismic() [selector c6d819f6]: reverts unless txType() == 0x4A.
    function requireSeismic() external view {
        require(_txType() == 0x4A);
    }
}
