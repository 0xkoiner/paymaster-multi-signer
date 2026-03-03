// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { _parseValidationData, ValidationData } from "lib/account-abstraction-v9/contracts/core/Helpers.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestPaymasterMode00 is Helpers {
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

        _etch7702(__7702_ADDRESS_EOA, address(simple7702Account));
    }

    function test_paymaster_entry_point_mode_0_all_bundlers_eoa_signer() external {
        (PackedUserOperation[] memory u, bytes32 userOpHash) =
            _getUserOp(__7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, 1);

        vm.prank(Constants.EP_V9_ADDRESS);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        assertEq(data.aggregator, address(0), "Not same aggregator address");
        assertEq(data.validUntil, type(uint48).max, "Not same aggregator validUntil");
        assertEq(data.validAfter, 0, "Not same aggregator validAfter");
        assertEq(context, hex"", "Not same aggregator context");
    }

    function test_paymaster_entry_point_mode_0_check_bundler_eoa_signer() external { }

    function test_paymaster_7702_account_mode_0_all_bundlers_eoa_signer() external { }

    function test_paymaster_7702_account_mode_0_check_bundler_eoa_signer() external { }

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
}

/**
 * @dev paymasterAndData for mode 0:
 *
 *  [0x0000000000000000000000000000000000000000][0x00000000000000000000000000000000][0x00000000000000000000000000000000][0x00][0x000000000000][0x000000000000]
 *  |        paymaster address 20 bytes        |     verification gas 16 bytes     |        postop gas 16 bytes        |  aB |   validUntil  |   validAfter  |
 *
 *  [0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000/00]
 *  |                                                       signature   64 or 65 bytes                                                    |
 */