// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { BaseAccount } from "lib/account-abstraction-v9/contracts/core/BaseAccount.sol";
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

    address internal random = makeAddr("random");
    uint256 internal balanceBefore;
    uint256 internal balanceAfter;

    function setUp() public override {
        super.setUp();

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        _deployment();

        _ethc();
        _etch7702(__7702_ADDRESS_EOA, address(simple7702Account));

        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);
        _deal(__7702_ADDRESS_EOA, Constants.ETH_1);
        _depositPaymaster();
    }

    // ------------------------------------------------------------------------------------
    //
    //                                       EOA
    //
    // ------------------------------------------------------------------------------------

    // Test VERIFYING_MODE with any bundler
    function test_paymaster_entry_point_mode_0_all_bundlers_eoa_signer() external {
        (PackedUserOperation[] memory u, bytes32 userOpHash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        vm.prank(Constants.EP_V9_ADDRESS);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context);
    }

    // Test VERIFYING_MODE with specific bundler
    function test_paymaster_entry_point_mode_0_check_bundler_eoa_signer() external {
        (PackedUserOperation[] memory u, bytes32 userOpHash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.SPECIFIC, SignerType.Secp256k1
        );

        vm.prank(Constants.EP_V9_ADDRESS, bundlers[0]);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context);
    }

    // Test VERIFYING_MODE with any bundler full cycle
    function test_paymaster_7702_account_mode_0_all_bundlers_eoa_signer() external {
        _assert(true, 0);
        bytes memory data = abi.encodeWithSelector(BaseAccount.execute.selector, random, 0.1 ether, hex"");
        (PackedUserOperation[] memory u,) =
            _getUserOp(__7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.Secp256k1);

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
    }

    // Test VERIFYING_MODE with specific bundler full cycle
    function test_paymaster_7702_account_mode_0_check_bundler_eoa_signer() external {
        _assert(true, 0);
        bytes memory data = abi.encodeWithSelector(BaseAccount.execute.selector, random, 0.1 ether, hex"");
        (PackedUserOperation[] memory u,) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.SPECIFIC, SignerType.Secp256k1
        );

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
    }

    // ------------------------------------------------------------------------------------
    //
    //                                         P256
    //
    // ------------------------------------------------------------------------------------

    // Test VERIFYING_MODE with any bundler
    function test_paymaster_entry_point_mode_0_all_bundlers_p256_extr_signer() external {
        prehash = false;
        (PackedUserOperation[] memory u, bytes32 userOpHash) =
            _getUserOp(__7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.P256);

        vm.prank(Constants.EP_V9_ADDRESS);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context);
    }

    // Test VERIFYING_MODE with any bundler
    function test_paymaster_entry_point_mode_0_all_bundlers_p256_non_extr_signer() external {
        prehash = true;
        (PackedUserOperation[] memory u, bytes32 userOpHash) =
            _getUserOp(__7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.P256);

        vm.prank(Constants.EP_V9_ADDRESS);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context);
    }

    // Test VERIFYING_MODE with specific bundler
    function test_paymaster_entry_point_mode_0_check_bundler_p256_extr_signer() external {
        prehash = false;

        (PackedUserOperation[] memory u, bytes32 userOpHash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.SPECIFIC, SignerType.P256
        );

        vm.prank(Constants.EP_V9_ADDRESS, bundlers[0]);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context);
    }

    // Test VERIFYING_MODE with specific bundler
    function test_paymaster_entry_point_mode_0_check_bundler_p256_non_extr_signer() external {
        prehash = true;

        (PackedUserOperation[] memory u, bytes32 userOpHash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ETH, Allow_Bundlers.SPECIFIC, SignerType.P256
        );

        vm.prank(Constants.EP_V9_ADDRESS, bundlers[0]);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context);
    }

    // Test VERIFYING_MODE with any bundler full cycle
    function test_paymaster_7702_account_mode_0_all_bundlers_p256_extr_signer() external {
        prehash = false;

        _assert(true, 0);
        bytes memory data = abi.encodeWithSelector(BaseAccount.execute.selector, random, 0.1 ether, hex"");
        (PackedUserOperation[] memory u,) =
            _getUserOp(__7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.P256);

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
    }

    // Test VERIFYING_MODE with any bundler full cycle
    function test_paymaster_7702_account_mode_0_all_bundlers_p256_non_extr_signer() external {
        prehash = true;

        _assert(true, 0);
        bytes memory data = abi.encodeWithSelector(BaseAccount.execute.selector, random, 0.1 ether, hex"");
        (PackedUserOperation[] memory u,) =
            _getUserOp(__7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.ALL, SignerType.P256);

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
    }

    // Test VERIFYING_MODE with specific bundler full cycle
    function test_paymaster_7702_account_mode_0_check_bundler_p256_extr_signer() external {
        prehash = false;

        _assert(true, 0);
        bytes memory data = abi.encodeWithSelector(BaseAccount.execute.selector, random, 0.1 ether, hex"");
        (PackedUserOperation[] memory u,) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.SPECIFIC, SignerType.P256
        );

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
    }

    // Test VERIFYING_MODE with specific bundler full cycle
    function test_paymaster_7702_account_mode_0_check_bundler_p256_non_extr_signer() external {
        prehash = true;

        _assert(true, 0);
        bytes memory data = abi.encodeWithSelector(BaseAccount.execute.selector, random, 0.1 ether, hex"");
        (PackedUserOperation[] memory u,) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ETH, Allow_Bundlers.SPECIFIC, SignerType.P256
        );

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
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

        _deploy(superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), webAuthnVerifier, bundlers);
    }

    // ------------------------------------------------------------------------------------
    //
    //                                    Assertion
    //
    // ------------------------------------------------------------------------------------

    function _assert(ValidationData memory _data, bytes memory _context) internal pure {
        assertEq(_data.aggregator, address(0), "Not same aggregator address");
        assertEq(_data.validUntil, type(uint48).max, "Not same aggregator validUntil");
        assertEq(_data.validAfter, 0, "Not same aggregator validAfter");
        assertEq(_context, hex"", "Not same aggregator context");
    }

    function _assert(bool _isBefore, uint256 _amount) internal {
        if (_isBefore) {
            balanceBefore = random.balance;
            assertEq(balanceBefore, 0, "Not same balance");
        } else {
            balanceAfter = random.balance;
            assertEq(balanceAfter, balanceBefore + _amount, "Not same balance");
        }
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