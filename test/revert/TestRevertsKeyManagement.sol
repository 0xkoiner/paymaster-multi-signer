// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestRevertsKeyManagement is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;
    Key internal random;

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
    //                       function addSigner(Key calldata _signer)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_addSigner_duplicate_key() external {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(random);

        vm.expectRevert(Errors.KeyAuthorized.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(random);
    }

    function test_revert_addSigner_admin_flag() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);

        vm.expectRevert(Errors.IncorrectSignerRole.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(random);
    }

    function test_revert_addSigner_superAdmin_flag() external {
        random = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, randomEoa);

        vm.expectRevert(Errors.IncorrectSignerRole.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.addSigner(random);
    }

    // ------------------------------------------------------------------------------------
    //
    //                       function authorizeAdmin(Key memory _key)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_authorizeAdmin_duplicate() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);

        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);

        vm.expectRevert(Errors.KeyAuthorized.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);
    }

    function test_revert_authorizeAdmin_superAdmin_flag() external {
        random = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, randomEoa);

        vm.expectRevert(Errors.IncorrectSignerRole.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);
    }

    function test_revert_authorizeAdmin_not_admin() external {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);

        vm.expectRevert(Errors.IncorrectSignerRole.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);
    }

    // ------------------------------------------------------------------------------------
    //
    //                       function removeSigner(bytes32 _signer)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_removeSigner_superAdmin() external {
        vm.expectRevert(Errors.KillSwitch.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.removeSigner(superAdmin.hash());
    }

    function test_revert_removeSigner_admin() external {
        vm.expectRevert(Errors.KillSwitch.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.removeSigner(admin.hash());
    }

    function test_revert_removeSigner_nonexistent() external {
        bytes32 fakeHash = keccak256("nonexistent");

        vm.expectRevert(Errors.KeyDoesNotExist.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.removeSigner(fakeHash);
    }

    // ------------------------------------------------------------------------------------
    //
    //                       function revoke(bytes32 _keyHash)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_revoke_nonexistent() external {
        bytes32 fakeHash = keccak256("nonexistent");

        vm.expectRevert(Errors.KeyDoesNotExist.selector);
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.revoke(fakeHash);
    }

    // ------------------------------------------------------------------------------------
    //
    //                       function getKey(bytes32 _keyHash)
    //
    // ------------------------------------------------------------------------------------

    function test_revert_getKey_nonexistent() external {
        bytes32 fakeHash = keccak256("nonexistent");

        vm.expectRevert(Errors.KeyDoesNotExist.selector);
        paymaster.getKey(fakeHash);
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
