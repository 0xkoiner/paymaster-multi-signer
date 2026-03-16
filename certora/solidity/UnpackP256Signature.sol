// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

contract UnpackP256Signature {
    function unpackP256Signature(bytes memory _signature)
        external
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
}