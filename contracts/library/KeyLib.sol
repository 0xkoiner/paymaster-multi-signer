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
            !_k.isSuperAdmin || _k.isAdmin || uint8(_k.keyType) < uint8(1) || _k.expiry != type(uint40).max
                || _k.publicKey.length == 0
        ) {
            return false;
        }
        return true;
    }

    function _isAdmin(Key memory _k) internal pure returns (bool) {
        if (
            _k.isSuperAdmin || !_k.isAdmin || uint8(_k.keyType) < uint8(1) || _k.expiry == type(uint40).max
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

    function _keyValidation(Key memory _k) internal view returns (bool) {
        if (_k.expiry < uint40(block.timestamp) || (_k.isSuperAdmin || _k.isAdmin) || _k.publicKey.length == 0) {
            return false;
        }

        return true;
    }

    function _validateSignatureLength(bytes calldata _signature, uint8 _signerType) internal pure {
        assembly {
            let len := _signature.length

            switch _signerType
            case 0x00 {
                // P256: length must be 128
                if iszero(eq(len, 128)) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
            }
            case 0x01 {
            // implement for Passkey/WebAuthn
            }
            case 0x02 {
                // Secp256k1: length must be 64 or 65
                if iszero(or(eq(len, 64), eq(len, 65))) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
            }
        }
    }
}
