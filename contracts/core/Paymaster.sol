// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Validations } from "./Validations.sol";
import { Eip7702Support } from "../library/Eip7702Support.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract Paymaster is Validations {
    constructor() { }

    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view override returns (bytes32) {
        bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(_userOp);
        bytes32 originalHash = super.getHash(_mode, _userOp);
        return keccak256(abi.encode(originalHash, overrideInitCodeHash));
    }
}
