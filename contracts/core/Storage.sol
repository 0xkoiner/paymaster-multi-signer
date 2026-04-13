// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { IStorage } from "../interface/IStorage.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { IWebAuthnVerifier } from "../interface/IWebAuthnVerifier.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract Storage is IStorage {
    /// @inheritdoc IStorage
    IEntryPoint public immutable entryPoint;

    /// @inheritdoc IStorage
    IWebAuthnVerifier public immutable webAuthnVerifier;

    /// @inheritdoc IStorage
    mapping(address account => bool isValidSigner) public signers;

    /// @inheritdoc IStorage
    mapping(address bundler => bool allowed) public isBundlerAllowed;

    /// @dev Set of key hashes for onchain enumeration of authorized keys.
    EnumerableSetLib.Bytes32Set internal keyHashes;

    /// @dev Mapping of key hash to the key in encoded form.
    mapping(bytes32 => LibBytes.BytesStorage) internal keyStorage;
}
