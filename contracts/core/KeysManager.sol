// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Storage } from "./Storage.sol";
import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { SignerType } from "../type/Types.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";

contract KeysManager is Storage {
    using EnumerableSetLib for *;
    using LibBytes for LibBytes.BytesStorage;

    function keyCount() public view virtual returns (uint256) {
        return keyHashes.length();
    }

    function keyAt(uint256 i) public view virtual returns (Key memory) {
        return getKey(keyHashes.at(i));
    }

    function getKey(bytes32 keyHash) public view virtual returns (Key memory key) {
        bytes memory data = keyStorage[keyHash].get();
        if (data.length == uint256(0)) revert Errors.KeyDoesNotExist();
        unchecked {
            uint256 n = data.length - 7; // 5 + 1 + 1 bytes of fixed length fields.
            uint256 packed = uint56(bytes7(LibBytes.load(data, n)));
            key.expiry = uint40(packed >> 16); // 5 bytes.
            key.keyType = SignerType(uint8(packed >> 8)); // 1 byte.
            key.isSuperAdmin = uint8(packed) != 0; // 1 byte.
            key.publicKey = LibBytes.truncate(data, n);
        }
    }
}
