// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Source for the `TXTYPE_PROBE_DEPLOY` bytecode used by the e2e tests in
// `../txtype.rs`. Stock Solidity — reads the EIP-2718 tx type and the
// signed-read flag from the 0x6A tx-context precompile via `staticcall`, no
// compiler builtin. See `README.md` for the exact compile command that
// reproduces the committed bytecode.
contract TxTypeProbe {
    address constant TX_CONTEXT = address(0x6A);

    // Empty input selects the tx type; a single 0x01 byte selects the signed-read flag.
    function _read(bytes memory selector) private view returns (uint256 v) {
        (bool ok, bytes memory ret) = TX_CONTEXT.staticcall(selector);
        require(ok && ret.length == 32, "TX_CONTEXT");
        v = abi.decode(ret, (uint256));
    }

    function _txType() private view returns (uint256) {
        return _read("");
    }

    function _signedRead() private view returns (uint256) {
        return _read(hex"01");
    }

    // isSeismic() [selector 02ce8088]: txType() == 0x4A as an abi bool.
    function isSeismic() external view returns (bool) {
        return _txType() == 0x4A;
    }

    // requireSeismic() [selector c6d819f6]: reverts unless txType() == 0x4A.
    function requireSeismic() external view {
        require(_txType() == 0x4A);
    }

    // isSignedRead() [selector 28782220]: the signed-read flag as an abi bool.
    function isSignedRead() external view returns (bool) {
        return _signedRead() == 1;
    }

    // requireSignedRead() [selector 6cac1460]: reverts unless the signed-read flag is 1.
    function requireSignedRead() external view {
        require(_signedRead() == 1);
    }

    // requireNotSignedRead() [selector 2dfeb92e]: reverts unless the signed-read flag is 0.
    function requireNotSignedRead() external view {
        require(_signedRead() == 0);
    }
}
