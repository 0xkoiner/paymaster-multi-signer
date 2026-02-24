// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract Storage {
    IEntryPoint public immutable entryPoint;

    mapping(address account => bool isValidSigner) public signers;

    mapping(address bundler => bool allowed) public isBundlerAllowed;
}
