// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { Events } from "../type/Events.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { SignerType } from "../type/Types.sol";
import { LibBit } from "@solady/src/utils/LibBit.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { ManagerAccessControl } from "./ManagerAccessControl.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";

contract KeysManager is ManagerAccessControl {
    using KeyLib for *;
    using EnumerableSetLib for *;
    using LibBytes for LibBytes.BytesStorage;

    function authorize(Key memory _key) public returns (bytes32 keyHash) {
        // Check the executor if the superAdmin
        keyHash = _addKey(_key);
        emit Events.Authorized(keyHash, _key);
    }

    function revoke(bytes32 _keyHash) public {
        // Check the executor if the superAdmin
        _removeKey(_keyHash);
        emit Events.Revoked(_keyHash);
    }

    function _addKey(Key memory _key) internal virtual returns (bytes32 keyHash) {
        keyHash = _key.hash();
        keyStorage[keyHash].set(
            abi.encodePacked(_key.publicKey, _key.expiry, _key.keyType, _key.isSuperAdmin, _key.isAdmin)
        );
        keyHashes.add(keyHash);
    }

    function _removeKey(bytes32 _keyHash) internal virtual {
        keyStorage[_keyHash].clear();
        if (!keyHashes.remove(_keyHash)) revert Errors.KeyDoesNotExist();
    }

    function keyCount() public view virtual returns (uint256) {
        return keyHashes.length();
    }

    function keyAt(uint256 _i) public view virtual returns (Key memory) {
        return getKey(keyHashes.at(_i));
    }

    function getKey(bytes32 _keyHash) public view virtual returns (Key memory key) {
        bytes memory data = keyStorage[_keyHash].get();
        if (data.length == uint256(0)) revert Errors.KeyDoesNotExist();
        unchecked {
            uint256 n = data.length - 8; // 5 + 1 + 1 + 1 bytes of fixed length fields.
            uint256 packed = uint64(bytes8(LibBytes.load(data, n)));
            key.expiry = uint40(packed >> 24); // 5 bytes.
            key.keyType = SignerType(uint8(packed >> 16)); // 1 byte.
            key.isSuperAdmin = uint8(packed >> 8) != 0; // 1 byte.
            key.isAdmin = uint8(packed) != 0; // 1 byte.
            key.publicKey = LibBytes.truncate(data, n);
        }
    }

    function getKeys() public view virtual returns (Key[] memory keys, bytes32[] memory hashes) {
        uint256 totalCount = keyCount();

        keys = new Key[](totalCount);
        hashes = new bytes32[](totalCount);

        uint256 validCount = 0;
        for (uint256 i = 0; i < totalCount; i++) {
            bytes32 keyHash = keyHashes.at(i);
            Key memory key = getKey(keyHash);

            if (LibBit.and(key.expiry != 0, block.timestamp > key.expiry)) {
                continue;
            }

            keys[validCount] = key;
            hashes[validCount] = keyHash;

            validCount++;
        }

        assembly {
            mstore(keys, validCount)
            mstore(hashes, validCount)
        }
    }
}
