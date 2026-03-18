// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Data } from "./Data.t.sol";
import { Constants } from "./Constants.sol";

contract Etch is Data {
    // Etch Deployed Bytecode
    function _ethc() internal {
        vm.etch(Constants.P256_ADDRESS, Constants.P256_DEPLOYED_BYTE_CODE);
        _label();
    }

    // Label canonical addresses
    function _label() internal {
        vm.label(Constants.P256_ADDRESS, "P256-Verifier");
    }
}
