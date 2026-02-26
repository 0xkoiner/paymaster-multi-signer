// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Data } from "../../data/Data.t.sol";
import { KeyLib } from "../../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../../contracts/type/Types.sol";

contract TestAddRemoveKey is Data {
    using KeyLib for *;

    error KeyDoesNotExist();

    Key private k;
    Key[] private ks;

    /// -------------------------------------------------------- super admin
    function test_authorize_key_super_admin() external {
        _authorizeSuperAdminKey();
        Key memory keyAuthorized = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorized });
    }

    function test_revoke_key_super_admin() external {
        _authorizeSuperAdminKey();

        bytes32 hash = k.hash();
        Key memory keyAuthorized = keysManager.getKey(hash);

        _assert({ _k: k, _keyAuthorized: keyAuthorized });

        _revokeKey(hash);

        vm.expectRevert(KeyDoesNotExist.selector);
        keyAuthorized = keysManager.getKey(hash);
    }

    /// -------------------------------------------------------- admin
    function test_authorize_key_admin() external {
        _authorizeAdminKey();
        Key memory keyAuthorized = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorized });
    }

    function test_revoke_key_admin() external {
        _authorizeAdminKey();

        bytes32 hash = k.hash();
        Key memory keyAuthorized = keysManager.getKey(hash);

        _assert({ _k: k, _keyAuthorized: keyAuthorized });

        _revokeKey(hash);

        vm.expectRevert(KeyDoesNotExist.selector);
        keyAuthorized = keysManager.getKey(hash);
    }

    /// -------------------------------------------------------- non-admin
    function test_authorize_non_admin() external {
        _authorizeNonAdminKey();
        Key memory keyAuthorized = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorized });
    }

    function test_revoke_key_non_admin() external {
        _authorizeNonAdminKey();

        bytes32 hash = k.hash();
        Key memory keyAuthorized = keysManager.getKey(hash);

        _assert({ _k: k, _keyAuthorized: keyAuthorized });

        _revokeKey(hash);

        vm.expectRevert(KeyDoesNotExist.selector);
        keyAuthorized = keysManager.getKey(hash);
    }

    /// -------------------------------------------------------- all types
    function test_authorize_all_types() external {
        _authorizeSuperAdminKey();
        Key memory keyAuthorizedSuperAdmin = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorizedSuperAdmin });

        _authorizeAdminKey();
        Key memory keyAuthorizedAdmin = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorizedAdmin });

        _authorizeNonAdminKey();
        Key memory keyAuthorizedNonAdmin = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorizedNonAdmin });
    }

    function test_revoke_key_all_types() external {
        _authorizeSuperAdminKey();
        Key memory keyAuthorizedSuperAdmin = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorizedSuperAdmin });
        ks.push(keyAuthorizedSuperAdmin);

        _authorizeAdminKey();
        Key memory keyAuthorizedAdmin = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorizedAdmin });
        ks.push(keyAuthorizedAdmin);

        _authorizeNonAdminKey();
        Key memory keyAuthorizedNonAdmin = keysManager.getKey(k.hash());
        _assert({ _k: k, _keyAuthorized: keyAuthorizedNonAdmin });
        ks.push(keyAuthorizedNonAdmin);

        for (uint256 i = 0; i < ks.length;) {
            bytes32 hash = ks[i].hash();

            _revokeKey(hash);

            vm.expectRevert(KeyDoesNotExist.selector);
            keysManager.getKey(hash);
            unchecked {
                ++i;
            }
        }
    }

    /// -------------------------------------------------------- helpers
    function _authorizeSuperAdminKey() internal {
        k.expiry = uint40(block.timestamp + 1);
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = true;
        k.isAdmin = false;
        k.publicKey = _getPubKeyWA(keccak256("cafe"), keccak256("babe"));

        vm.prank(address(0xbabe));
        keysManager.authorize(k);
    }

    function _authorizeAdminKey() internal {
        k.expiry = uint40(block.timestamp + 1);
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = false;
        k.isAdmin = true;
        k.publicKey = _getPubKeyWA(keccak256("cafe-1"), keccak256("babe-1"));

        vm.prank(address(0xbabe));
        keysManager.authorize(k);
    }

    function _authorizeNonAdminKey() internal {
        k.expiry = uint40(block.timestamp + 1);
        k.keyType = SignerType.WebAuthnP256;
        k.isSuperAdmin = false;
        k.isAdmin = false;
        k.publicKey = _getPubKeyWA(keccak256("cafe-2"), keccak256("babe-2"));

        vm.prank(address(0xbabe));
        keysManager.authorize(k);
    }

    function _revokeKey(bytes32 _hash) internal {
        vm.prank(address(0xbabe));
        keysManager.revoke(_hash);
    }

    function _getPubKeyWA(bytes32 _x, bytes32 _y) internal pure returns (bytes memory) {
        return abi.encode(_x, _y);
    }

    function _assert(Key memory _k, Key memory _keyAuthorized) internal pure {
        assertEq(_k.expiry, _keyAuthorized.expiry, "Not same expiry");
        assertEq(uint8(_k.keyType), uint8(_keyAuthorized.keyType), "Not same type");
        assertEq(_k.isSuperAdmin, _keyAuthorized.isSuperAdmin, "Not same isSuperAdmin");
        assertEq(_k.isAdmin, _keyAuthorized.isAdmin, "Not same isSuperAdmin");
        assertEq(_k.publicKey, _keyAuthorized.publicKey, "Not same isSuperAdmin");
    }
}
