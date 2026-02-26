// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { EfficientHashLib } from "@solady/src/utils/EfficientHashLib.sol";
import { FixedPointMathLib as Math } from "@solady/src/utils/FixedPointMathLib.sol";

using LibBytes for LibBytes.BytesStorage;

library KeyLib {
    function hash(Key memory _key) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint8(_key.keyType), uint256(keccak256(_key.publicKey)));
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
}
