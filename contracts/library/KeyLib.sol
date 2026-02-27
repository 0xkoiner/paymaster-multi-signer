// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Errors } from "../type/Errors.sol";
import { Key, SignerType } from "../type/Types.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { EfficientHashLib } from "@solady/src/utils/EfficientHashLib.sol";
import { FixedPointMathLib as Math } from "@solady/src/utils/FixedPointMathLib.sol";

using LibBytes for LibBytes.BytesStorage;

library KeyLib {
    function hash(Key memory _key) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint8(_key.keyType), uint256(keccak256(_key.publicKey)));
    }

    function hash(address _msgSender) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint8(SignerType.Secp256k1), uint256(keccak256(abi.encode(_msgSender))));
    }

    function _isSuperAdmin(LibBytes.BytesStorage storage _s) internal view returns (bool) {
        uint256 encodedLength = _s.length();
        if (encodedLength == uint256(0)) revert Errors.KeyDoesNotExist();
        return _s.uint8At(Math.rawSub(encodedLength, 2)) != 0;
    }

    function _isAdmin(LibBytes.BytesStorage storage _s) internal view returns (bool) {
        uint256 encodedLength = _s.length();
        if (encodedLength == uint256(0)) revert Errors.KeyDoesNotExist();
        return _s.uint8At(Math.rawSub(encodedLength, 1)) != 0;
    }

    function _isSuperAdmin(Key memory _k) internal pure returns (bool) {
        if (
            !_k.isSuperAdmin || _k.isAdmin || uint8(_k.keyType) > uint8(1) || _k.expiry != type(uint40).max
                || _k.publicKey.length == 0
        ) {
            return false;
        }
        return true;
    }

    function _isAdmin(Key memory _k) internal pure returns (bool) {
        if (
            _k.isSuperAdmin || !_k.isAdmin || uint8(_k.keyType) > uint8(1) || _k.expiry == type(uint40).max
                || _k.publicKey.length == 0
        ) {
            return false;
        }
        return true;
    }

    function _isSigner(Key memory _k) internal pure returns (bool) {
        if (_k.isSuperAdmin || _k.isAdmin || _k.expiry == type(uint40).max || _k.publicKey.length == 0) {
            return false;
        }
        return true;
    }
}
