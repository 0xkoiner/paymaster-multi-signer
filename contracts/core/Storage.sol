// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract Storage {
    IEntryPoint public immutable entryPoint;

    mapping(address account => bool isValidSigner) public signers;

    mapping(address bundler => bool allowed) public isBundlerAllowed;

    /// @dev Set of key hashes for onchain enumeration of authorized keys.
    EnumerableSetLib.Bytes32Set keyHashes;

    /// @dev Mapping of key hash to the key in encoded form.
    mapping(bytes32 => LibBytes.BytesStorage) keyStorage;
}
