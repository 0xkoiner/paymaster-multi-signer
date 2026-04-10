// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType, PostOpMode } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestRevertsPaymasterValidation is Helpers {
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

        _deal(address(paymaster), Constants.ETH_1);
        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);

        _depositPaymaster();
    }

    // ------------------------------------------------------------------------------------
    //
    //    function validatePaymasterUserOp — SenderNotEntryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_validatePaymasterUserOp_not_entryPoint() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;

        vm.expectRevert(Errors.SenderNotEntryPoint.selector);
        vm.prank(randomEoa);
        paymaster.validatePaymasterUserOp(u, bytes32(0), 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    function postOp — SenderNotEntryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_postOp_not_entryPoint() external {
        vm.expectRevert(Errors.SenderNotEntryPoint.selector);
        vm.prank(randomEoa);
        paymaster.postOp(PostOpMode.opSucceeded, hex"", 0, 0);
    }

    // ------------------------------------------------------------------------------------
    //
    //    function executeBatch — SenderNotEntryPoint
    //
    // ------------------------------------------------------------------------------------

    function test_revert_validateUserOp_not_entryPoint() external {
        PackedUserOperation memory u;
        u.sender = randomEoa;

        vm.expectRevert(Errors.SenderNotEntryPoint.selector);
        vm.prank(randomEoa);
        paymaster.validateUserOp(u, bytes32(0), 0);
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
