// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Etch } from "../data/Etch.t.sol";
import { Constants } from "../data/Constants.sol";
import { P256 } from "../../contracts/library/P256.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";

contract SignerHelpers is Etch {
    // ------------------------------------------------------------------------------------
    //
    //                                       Enum/Structs
    //
    // ------------------------------------------------------------------------------------

    enum TypeOfKey {
        SUPER_ADMIN,
        ADMIN,
        SIGNER
    }

    // ------------------------------------------------------------------------------------
    //
    //                                       Storage
    //
    // ------------------------------------------------------------------------------------

    bool internal transient prehash;

    // ------------------------------------------------------------------------------------
    //
    //                                       Helpers
    //
    // ------------------------------------------------------------------------------------

    function _createKeySecp256k1(TypeOfKey _typeOfKey, address _eoa) internal pure returns (Key memory k) {
        k.expiry = _typeOfKey == TypeOfKey.SUPER_ADMIN ? type(uint40).max : Constants.EXPIRY;
        k.keyType = SignerType.Secp256k1;
        k.isSuperAdmin = _typeOfKey == TypeOfKey.SUPER_ADMIN ? true : false;
        k.isAdmin = _typeOfKey == TypeOfKey.ADMIN ? true : false;
        k.publicKey = _encodeKey(_eoa);
    }

    function _encodeKey(address _eoa) internal pure returns (bytes memory) {
        return abi.encode(_eoa);
    }

    function _signHashWithP256(bytes32 _hash, bool _prehash) internal returns (bytes memory signature) {
        string[] memory cmd = new string[](6);
        cmd[0] = "npx";
        cmd[1] = "ts-node";
        cmd[2] = "--esm";
        cmd[3] = "script/P256.ts";
        cmd[4] = vm.toString(_hash);
        cmd[5] = _prehash ? "non-extractable" : "extractable";
        signature = vm.ffi(cmd);
    }
}
