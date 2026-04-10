// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestCoverageKeysManager is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;

    address internal randomEoa;

    function setUp() public override {
        super.setUp();

        randomEoa = makeAddr("random");

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();
    }

    // ------------------------------------------------------------------------------------
    //
    //    getKeys — expired key filtered out (lines 81, 91-92)
    //
    // ------------------------------------------------------------------------------------

    function test_getKeys_filters_expired_key() external {
        // Add a signer with very short expiry (current timestamp + 1)
        Key memory shortLived;
        shortLived.expiry = uint40(block.timestamp + 1);
        shortLived.keyType = SignerType.Secp256k1;
        shortLived.isSuperAdmin = false;
        shortLived.isAdmin = false;
        shortLived.publicKey = abi.encode(randomEoa);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(shortLived);

        // Before expiry: 4 keys (super, admin, signer, shortLived)
        (Key[] memory keysBefore,) = paymaster.getKeys();
        assertEq(keysBefore.length, 4, "Should have 4 keys before expiry");

        // Warp past expiry
        vm.warp(block.timestamp + 2);

        // After expiry: 3 keys (shortLived filtered out)
        (Key[] memory keysAfter,) = paymaster.getKeys();
        assertEq(keysAfter.length, 3, "Should have 3 keys after expiry");
    }

    // ------------------------------------------------------------------------------------
    //
    //                                        Helpers
    //
    // ------------------------------------------------------------------------------------

    function _deployment() internal {
        Key[] memory kS = new Key[](1);
        kS[0] = signer;

        _deploy(superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), webAuthnVerifier, bundlers);
    }
}
