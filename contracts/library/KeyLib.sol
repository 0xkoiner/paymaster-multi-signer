// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Errors } from "../type/Errors.sol";
import { Key, SignerType } from "../type/Types.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { WebAuthn } from "../../contracts/library/WebAuthn.sol";
import { EfficientHashLib } from "@solady/src/utils/EfficientHashLib.sol";
import { FixedPointMathLib as Math } from "@solady/src/utils/FixedPointMathLib.sol";

using LibBytes for LibBytes.BytesStorage;

library KeyLib {
    uint256 private constant __DEPOSIT_SEL = 0xd0e30db000000000000000000000000000000000000000000000000000000000;
    uint256 private constant __ADD_STAKE_SEL = 0x0396cb6000000000000000000000000000000000000000000000000000000000;
    uint256 private constant __UNLOCK_STAKE_SEL = 0xbb9fe6bf00000000000000000000000000000000000000000000000000000000;
    uint256 private constant __ADD_SIGNER_SEL = 0x56864ab100000000000000000000000000000000000000000000000000000000;

    function hash(Key memory _key) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint8(_key.keyType), uint256(keccak256(_key.publicKey)));
    }

    function hash(address _msgSender) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint8(SignerType.Secp256k1), uint256(keccak256(abi.encode(_msgSender))));
    }

    function hash(bytes32 _qx, bytes32 _qy, SignerType _signerType) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint8(_signerType), uint256(keccak256(abi.encode(_qx, _qy))));
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
        if (_k.expiry < uint40(block.timestamp)) {
            return false;
        }

        return true;
    }

    function _validateSignatureLength(bytes memory _signature, uint8 _signerType) internal pure {
        assembly {
            let len := mload(_signature)

            switch _signerType
            case 0x00 {
                // P256: length must be 128 (extractable) or 129 (non-extractable flag)
                if iszero(or(eq(len, 128), eq(len, 129))) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
            }
            case 0x01 {
                // WebAuthn: abi.encode(WebAuthnAuth) || qx(32) || qy(32)
                // Min length: 0x160 (352) = 7 head words + 2 length words + qx + qy
                if lt(len, 0x160) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
                // authenticatorData length at data offset 0xe0
                let adLen := mload(add(_signature, 0x100))
                let adPad := and(add(adLen, 0x1f), not(0x1f))
                // Overflow guard: ceil32 wraps if adLen > 2^256-32
                if lt(adPad, adLen) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
                // Bounds check before reading cjLen
                if gt(add(0x120, adPad), len) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
                // clientDataJSON length
                let cjLen := mload(add(add(_signature, 0x120), adPad))
                let cjPad := and(add(cjLen, 0x1f), not(0x1f))
                if lt(cjPad, cjLen) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
                // Expected = 0x160 + adPad + cjPad
                let expected := add(0x160, add(adPad, cjPad))
                if iszero(eq(len, expected)) {
                    mstore(0x00, 0xf95eeeac)
                    revert(0x1c, 0x04)
                }
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

    function _unpackP256Signature(bytes memory _signature)
        internal
        pure
        returns (bytes32 r, bytes32 s, bytes32 qx, bytes32 qy, bool prehash)
    {
        assembly {
            let len := mload(_signature)
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            qx := mload(add(_signature, 0x60))
            qy := mload(add(_signature, 0x80))
            // If 129 bytes, last byte is the prehash flag (non-extractable key)
            if eq(len, 129) { prehash := iszero(iszero(byte(0, mload(add(_signature, 0xa0))))) }
        }
    }

    function _unpackWebAuthnCoordinats(bytes memory _signature) internal pure returns (bytes32 qx, bytes32 qy) {
        uint256 len = _signature.length;
        assembly {
            qx := mload(add(_signature, sub(len, 0x20)))
            qy := mload(add(_signature, len))
        }
    }

    function _isAllowedSelector(bytes4 _sel) internal pure returns (bool isValid) {
        assembly {
            /// @dev:  deposit()::0xd0e30db0  addStake(uint32)::0x0396cb60  unlockStake()::0xbb9fe6bf
            /// addSigner(Key)::0x56864ab1
            isValid := or(
                or(eq(_sel, __DEPOSIT_SEL), eq(_sel, __ADD_STAKE_SEL)),
                or(eq(_sel, __UNLOCK_STAKE_SEL), eq(_sel, __ADD_SIGNER_SEL))
            )
        }
    }
}
