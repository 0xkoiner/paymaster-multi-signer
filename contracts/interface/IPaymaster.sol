// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

interface IPaymaster {
    function deposit() external payable;
    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) external view returns (bytes32);
}
