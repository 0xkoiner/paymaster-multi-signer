// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

contract ValidateSignatureLength {
    function validateSignatureLength(bytes memory _signature, uint8 _signerType) public pure {
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
}