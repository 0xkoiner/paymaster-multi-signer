// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Data } from "../../data/Data.t.sol";
import { KeyLib } from "../../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../../contracts/type/Types.sol";

contract TestAddRemoveKey is Data {
    using KeyLib for *;

    error KeyDoesNotExist();

    Key private k;

    function test_authorize_key_super_admin() external {
        k.expiry = uint40(block.timestamp + 1);
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = true;
        k.isAdmin = false;
        k.publicKey = _getPubKeyWA(keccak256("cafe"), keccak256("babe"));

        vm.prank(address(0xbabe));
        keysManager.authorize(k);

        Key memory keyAuthorized = keysManager.getKey(k.hash());

        _assert({ _k: k, _keyAuthorized: keyAuthorized });
    }

    function test_revoke_key_super_admin() external {
        k.expiry = uint40(block.timestamp + 1);
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = true;
        k.isAdmin = false;
        k.publicKey = _getPubKeyWA(keccak256("cafe"), keccak256("babe"));

        vm.prank(address(0xbabe));
        keysManager.authorize(k);

        bytes32 hash = k.hash();
        Key memory keyAuthorized = keysManager.getKey(hash);

        _assert({ _k: k, _keyAuthorized: keyAuthorized });

        vm.prank(address(0xbabe));
        keysManager.revoke(hash);

        vm.expectRevert(KeyDoesNotExist.selector);
        keyAuthorized = keysManager.getKey(hash);
    }

    function _getPubKeyWA(bytes32 _x, bytes32 _y) internal returns (bytes memory) {
        return abi.encode(_x, _y);
    }

    function _assert(Key memory _k, Key memory _keyAuthorized) internal view {
        assertEq(_k.expiry, _keyAuthorized.expiry, "Not same expiry");
        assertEq(uint8(_k.keyType), uint8(_keyAuthorized.keyType), "Not same type");
        assertEq(_k.isSuperAdmin, _keyAuthorized.isSuperAdmin, "Not same isSuperAdmin");
        assertEq(_k.isAdmin, _keyAuthorized.isAdmin, "Not same isSuperAdmin");
        assertEq(_k.publicKey, _keyAuthorized.publicKey, "Not same isSuperAdmin");
    }
}
