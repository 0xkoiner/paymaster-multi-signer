// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { AAHelpers } from "./AAHelpers.t.sol";
import { Constants } from "../data/Constants.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";

contract Helpers is AAHelpers {
    enum TypeOfKey {
        SUPER_ADMIN,
        ADMIN,
        SIGNER
    }

    function _createKeySecp256k1(TypeOfKey _typeOfKey, address _eoa) internal returns (Key memory k) {
        k.expiry = _typeOfKey == TypeOfKey.SUPER_ADMIN ? type(uint40).max : Constants.EXPIRY;
        k.keyType = SignerType.Secp256k1;
        k.isSuperAdmin = _typeOfKey == TypeOfKey.SUPER_ADMIN ? true : false;
        k.isAdmin = _typeOfKey == TypeOfKey.ADMIN ? true : false;
        k.publicKey = _encodeKey(_eoa);
    }

    function _encodeKey(address _eoa) internal returns (bytes memory) {
        return abi.encode(_eoa);
    }
}
