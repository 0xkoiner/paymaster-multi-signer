// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestRevertsAccessControl is Helpers {
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

        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);
        _deal(address(paymaster), Constants.ETH_1);

        _depositPaymaster();
    }

    // ------------------------------------------------------------------------------------
    //
    //           onlySuperAdminOrAdminKeyOrEp — random EOA rejected
    //
    // ------------------------------------------------------------------------------------

    function test_revert_addSigner_random_eoa() external {
        random = _createKeySecp256k1(TypeOfKey.SIGNER, randomEoa);

        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.addSigner(random);
    }

    function test_revert_deposit_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.deposit();
    }

    function test_revert_addStake_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.addStake(Constants.UNSTAKE_DELAY);
    }

    function test_revert_unlockStake_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.unlockStake();
    }

    // ------------------------------------------------------------------------------------
    //
    //           onlySuperAdminKeyOrEp — random EOA rejected
    //
    // ------------------------------------------------------------------------------------

    function test_revert_authorizeAdmin_random_eoa() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);

        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.authorizeAdmin(random);
    }

    function test_revert_revoke_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.revoke(signer.hash());
    }

    function test_revert_removeSigner_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.removeSigner(signer.hash());
    }

    function test_revert_withdrawTo_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.withdrawTo(payable(randomEoa), Constants.ETH_0_1);
    }

    function test_revert_withdrawStake_random_eoa() external {
        vm.expectRevert(abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, randomEoa));
        vm.prank(randomEoa);
        paymaster.withdrawStake(payable(randomEoa));
    }

    // ------------------------------------------------------------------------------------
    //
    //           onlySuperAdminKeyOrEp — admin rejected
    //
    // ------------------------------------------------------------------------------------

    function test_revert_authorizeAdmin_admin() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);

        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER__ADMIN_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);
    }

    function test_revert_revoke_admin() external {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER__ADMIN_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        paymaster.revoke(signer.hash());
    }

    function test_revert_removeSigner_admin() external {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER__ADMIN_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        paymaster.removeSigner(signer.hash());
    }

    function test_revert_withdrawTo_admin() external {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER__ADMIN_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        paymaster.withdrawTo(payable(__PAYMASTER__ADMIN_ADDRESS_EOA), Constants.ETH_0_1);
    }

    function test_revert_withdrawStake_admin() external {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER__ADMIN_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        paymaster.withdrawStake(payable(__PAYMASTER__ADMIN_ADDRESS_EOA));
    }

    // ------------------------------------------------------------------------------------
    //
    //           onlySuperAdminKeyOrEp — signer rejected
    //
    // ------------------------------------------------------------------------------------

    function test_revert_authorizeAdmin_signer() external {
        random = _createKeySecp256k1(TypeOfKey.ADMIN, randomEoa);

        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER_SIGNER_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER_SIGNER_ADDRESS_EOA);
        paymaster.authorizeAdmin(random);
    }

    function test_revert_removeSigner_signer() external {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER_SIGNER_ADDRESS_EOA)
        );
        vm.prank(__PAYMASTER_SIGNER_ADDRESS_EOA);
        paymaster.removeSigner(signer.hash());
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
