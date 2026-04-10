// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Etch } from "../data/Etch.t.sol";
import { Constants } from "../data/Constants.sol";
import { P256 } from "../../contracts/library/P256.sol";
import {stdJson} from "../../lib/forge-std/src/StdJson.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { WebAuthn } from "../../contracts/library/WebAuthn.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";

contract SignerHelpers is Etch {
    using KeyLib for *;

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

    struct P256PubKey {
        bytes32 qx;
        bytes32 qy;
    }

    // ------------------------------------------------------------------------------------
    //
    //                                       Storage
    //
    // ------------------------------------------------------------------------------------

    Key private k;

    bool internal transient prehash;

    string private _root_path = vm.projectRoot();

    // ------------------------------------------------------------------------------------
    //
    //                                       Helpers
    //
    // ------------------------------------------------------------------------------------

    function _createKeyP256(TypeOfKey _typeOfKey) internal pure returns (Key memory k) {
        k.expiry = _typeOfKey == TypeOfKey.SUPER_ADMIN ? type(uint40).max : Constants.EXPIRY;
        k.keyType = SignerType.P256;
        k.isSuperAdmin = _typeOfKey == TypeOfKey.SUPER_ADMIN ? true : false;
        k.isAdmin = _typeOfKey == TypeOfKey.ADMIN ? true : false;
        k.publicKey = _encodeKey(keccak256("x-p256"), keccak256("y-p256"));
    }

    function _createKeyWebAuthn(TypeOfKey _typeOfKey) internal pure returns (Key memory k) {
        k.expiry = _typeOfKey == TypeOfKey.SUPER_ADMIN ? type(uint40).max : Constants.EXPIRY;
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = _typeOfKey == TypeOfKey.SUPER_ADMIN ? true : false;
        k.isAdmin = _typeOfKey == TypeOfKey.ADMIN ? true : false;
        k.publicKey = _encodeKey(keccak256("x-webAuthn"), keccak256("y-webAuthn"));
    }

    function _createKeyWebAuthn(TypeOfKey _typeOfKey, bytes32 _x, bytes32 _y) internal pure returns (Key memory k) {
        k.expiry = _typeOfKey == TypeOfKey.SUPER_ADMIN ? type(uint40).max : Constants.EXPIRY;
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = _typeOfKey == TypeOfKey.SUPER_ADMIN ? true : false;
        k.isAdmin = _typeOfKey == TypeOfKey.ADMIN ? true : false;
        k.publicKey = _encodeKey(_x, _y);
    }

    function _createKeySecp256k1(TypeOfKey _typeOfKey, address _eoa) internal pure returns (Key memory k) {
        k.expiry = _typeOfKey == TypeOfKey.SUPER_ADMIN ? type(uint40).max : Constants.EXPIRY;
        k.keyType = SignerType.Secp256k1;
        k.isSuperAdmin = _typeOfKey == TypeOfKey.SUPER_ADMIN ? true : false;
        k.isAdmin = _typeOfKey == TypeOfKey.ADMIN ? true : false;
        k.publicKey = _encodeKey(_eoa);
    }

    function _fetchWebAuthnSigner(
        string memory _path,
        string memory _key
    )
        internal
        view
        returns (P256PubKey memory signer)
    {
        string memory path = string.concat(_root_path, _path);
        string memory json = vm.readFile(path);

        signer.qx = stdJson.readBytes32(json, string.concat(".", _key, ".x"));
        signer.qy = stdJson.readBytes32(json, string.concat(".", _key, ".y"));
    }

    // Pack Eoa Signature
    function _packEoaSigner(uint256 _pK, bytes32 _hash) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pK, _hash);
        signature = abi.encodePacked(abi.encodePacked(SignerType.Secp256k1, r, s, v));
    }

    function _packWebAuthnSigner(bytes32 _hash) internal virtual returns (bytes memory) {
        (bytes memory signature,) = _signHashWithWebAuthnKey(_hash, Constants.WEBAUTHN_SUPER_ADMIN_PK);
        return abi.encodePacked(SignerType.WebAuthnP256, signature);
    }
    
    function _encodeKey(address _eoa) internal pure returns (bytes memory) {
        return abi.encode(_eoa);
    }

    function _encodeKey(bytes32 _x, bytes32 _y) internal pure returns (bytes memory) {
        return abi.encode(_x, _y);
    }

    function _encodeWebAuthn(
        WebAuthn.WebAuthnAuth memory _webAuthnAuth,
        bytes32 _x,
        bytes32 _y
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(WebAuthn.encodeAuth(_webAuthnAuth), _x, _y);
    }

    function _signHashWithP256(
        bytes32 _hash,
        bool _prehash
    )
        internal
        returns (bytes memory signature, P256PubKey memory pK)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "npx";
        cmd[1] = "tsx";
        cmd[2] = "script/P256.ts";
        cmd[3] = vm.toString(_hash);
        cmd[4] = _prehash ? "non-extractable" : "extractable";
        signature = vm.ffi(cmd);
        (,, pK.qx, pK.qy,) = signature._unpackP256Signature();
    }

    function _signHashWithWebAuthn(bytes32 _hash) internal returns (bytes memory signature, P256PubKey memory pK) {
        string[] memory cmd = new string[](4);
        cmd[0] = "npx";
        cmd[1] = "tsx";
        cmd[2] = "script/WebAuthn.ts";
        cmd[3] = vm.toString(_hash);
        signature = vm.ffi(cmd);
        (pK.qx, pK.qy) = signature._unpackWebAuthnCoordinats();
    }

    function _signHashWithWebAuthnKey(
        bytes32 _hash,
        string memory _privateKey
    ) internal returns (bytes memory signature, P256PubKey memory pK) {
        string[] memory cmd = new string[](5);
        cmd[0] = "npx";
        cmd[1] = "tsx";
        cmd[2] = "script/WebAuthn.ts";
        cmd[3] = vm.toString(_hash);
        cmd[4] = _privateKey;
        signature = vm.ffi(cmd);
        (pK.qx, pK.qy) = signature._unpackWebAuthnCoordinats();
    }

    function _authorizeSigner(P256PubKey memory _pK, SignerType _signerType) internal {
        k.expiry = uint40(block.timestamp + 1);
        k.keyType = _signerType;
        k.isSuperAdmin = false;
        k.isAdmin = false;
        k.publicKey = _encodeKey(_pK.qx, _pK.qy);

        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        paymaster.addSigner(k);
    }
}
