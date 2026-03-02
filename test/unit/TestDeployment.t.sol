// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestDeployment is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;

    function setUp() public override {
        super.setUp();

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();
    }

    // Test full deployment and states
    function test_after_deploy() external {
        uint256 keyCount = paymaster.keyCount();
        (Key[] memory keys, bytes32[] memory hashes) = paymaster.getKeys();

        assertEq(keyCount, 3);
        _assert(keys[0], superAdmin, hashes[0]);
        _assert(keys[1], admin, hashes[1]);
        _assert(keys[2], signer, hashes[2]);
        _assertBundlers();
    }

    // ------------------------------------------------------------------------------------
    //
    //                                        Helpers
    //
    // ------------------------------------------------------------------------------------

    // Deploy Paymaster
    function _deployment() internal {
        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        _deploy(superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), bundlers);
    }

    // ------------------------------------------------------------------------------------
    //
    //                                        Assertion
    //
    // ------------------------------------------------------------------------------------

    // Assert states (keys, keyhash, entrypoint)
    function _assert(Key memory _k, Key memory _kStorage, bytes32 _keyHash) internal view {
        assertEq(_k.expiry, _kStorage.expiry, "Not Same expiry");
        assertEq(uint8(_k.keyType), uint8(_kStorage.keyType), "Not Same keyType");
        assertEq(_k.isSuperAdmin, _kStorage.isSuperAdmin, "Not Same isSuperAdmin");
        assertEq(_k.isAdmin, _kStorage.isAdmin, "isAdmin");
        assertEq(_k.publicKey, _kStorage.publicKey, "Not Same publicKey");

        assertEq(_keyHash, _kStorage.hash(), "Not Same keyHash");
        
        assertEq(Constants.EP_V9_ADDRESS, address(paymaster.entryPoint()), "Not Same entryPoint");
    }

    // Assert bundlers list
    function _assertBundlers() internal {
        for (uint256 i = 0; i < bundlers.length;) {
            assertTrue(paymaster.isBundlerAllowed(bundlers[i]), "The bundler is not allowed");
            unchecked {
                ++i;
            }
        }
    }
}
