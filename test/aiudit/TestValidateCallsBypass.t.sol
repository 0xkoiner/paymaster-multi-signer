// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Errors } from "../../contracts/type/Errors.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { IStakeManager } from "lib/account-abstraction-v9/contracts/interfaces/IStakeManager.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

/// @title  POC — _validateCalls early-return bypass
/// @notice An admin key can smuggle an unauthorized call (withdrawTo) past
///         _validateCalls by placing an allowed selector (deposit) first in
///         the executeBatch array. The loop returns after checking call[0]
///         and never inspects call[1].
contract TestValidateCallsBypass is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;

    address payable internal attacker;

    Call[] internal calls;

    function setUp() public override {
        super.setUp();

        attacker = payable(makeAddr("attacker"));

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-poc"), 2);

        _deployment();

        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);
        _deal(__PAYMASTER__ADMIN_ADDRESS_EOA, Constants.ETH_1);
        _deal(address(paymaster), Constants.ETH_1);

        // Deposit 1 ETH so there is enough buffer after gas deductions
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        paymaster.deposit{ value: Constants.ETH_1 }();
    }

    // ------------------------------------------------------------------------------------
    //
    //                                     POC — Exploit
    //
    // ------------------------------------------------------------------------------------

    /// @notice Admin cannot drain the paymaster deposit via withdrawTo hidden
    ///         behind an allowed deposit() call — _validateCalls now checks ALL
    ///         calls in the batch and rejects the unauthorized withdrawTo.
    function test_admin_bypass_validateCalls_withdrawTo_is_blocked() external {
        uint256 drainAmount = 0.5 ether;

        // --- Build malicious batch ---
        // call[0]: deposit()    — allowed selector
        // call[1]: withdrawTo() — superAdmin-only, now correctly rejected
        calls.push(_encodeCall(address(paymaster), 0, abi.encodeWithSelector(paymaster.deposit.selector)));
        calls.push(
            _encodeCall(
                address(paymaster), 0, abi.encodeWithSelector(paymaster.withdrawTo.selector, attacker, drainAmount)
            )
        );

        bytes memory data = abi.encodeWithSelector(paymaster.executeBatch.selector, calls);

        // --- Sign with admin key (NOT superAdmin) ---
        (PackedUserOperation[] memory u, bytes32 hash) = _getUserOp(
            address(paymaster), __PAYMASTER_ADMIN_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        u[0].signature = _packEoaSigner(__PAYMASTER_ADMIN_EOA, hash);

        // --- EntryPoint rejects with AA24 (signature/validation failure) ---
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        _relayUserOp(u);

        // --- Assert attacker received nothing ---
        assertEq(attacker.balance, 0, "Attacker should have received nothing");
    }

    // ------------------------------------------------------------------------------------
    //
    //                                  Sanity — Direct Revert
    //
    // ------------------------------------------------------------------------------------

    /// @notice Confirm that an admin calling withdrawTo directly is rejected.
    function test_admin_cannot_withdrawTo_directly() external {
        vm.prank(__PAYMASTER__ADMIN_ADDRESS_EOA);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AccessControlUnauthorizedAccount.selector, __PAYMASTER__ADMIN_ADDRESS_EOA)
        );
        paymaster.withdrawTo(attacker, 0.1 ether);
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
