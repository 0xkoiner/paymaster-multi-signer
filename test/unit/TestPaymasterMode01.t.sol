// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { ERC20PostOpContext } from "../../contracts/type/Types.sol";
import { BaseAccount } from "lib/account-abstraction-v9/contracts/core/BaseAccount.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { IERC20 } from "../../lib/openzeppelin-contracts-v5.5.0/contracts/token/ERC20/IERC20.sol";
import { _parseValidationData, ValidationData } from "lib/account-abstraction-v9/contracts/core/Helpers.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract TestPaymasterMode01 is Helpers {
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
    uint256 internal balanceBeforeErc20;
    uint256 internal balanceAfterErc20;

    Call[] internal calls;

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

        _mint(__7702_ADDRESS_EOA, Constants.ERC20_MINT_VAL_100_18, true);
    }

    // Test ERC20_MODE with any bundler
    function test_paymaster_entry_point_mode_1_all_bundlers_eoa_signer() external {
        (PackedUserOperation[] memory u, bytes32 userOpHash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ERC20, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        vm.prank(Constants.EP_V9_ADDRESS);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context, userOpHash);
    }

    // Test ERC20_MODE with specific bundler
    function test_paymaster_entry_point_mode_1_check_bundler_eoa_signer() external {
        (PackedUserOperation[] memory u, bytes32 userOpHash) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, hex"", Sponsor_Type.ERC20, Allow_Bundlers.SPECIFIC, SignerType.Secp256k1
        );

        vm.prank(Constants.EP_V9_ADDRESS, bundlers[0]);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(u[0], userOpHash, 0);
        (ValidationData memory data) = _parseValidationData(validationData);

        _assert(data, context, userOpHash);
    }

    // Test ERC20_MODE with any bundler full cycle
    function test_paymaster_7702_account_mode_1_all_bundlers_eoa_signer() external {
        _assert(true, 0);
        _assertErc20(true, address(sponsorERC20), __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        calls.push(_encodeCall(random, 0.1 ether, hex""));
        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));

        bytes memory data = abi.encodeWithSelector(BaseAccount.executeBatch.selector, calls);

        (PackedUserOperation[] memory u,) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ERC20, Allow_Bundlers.ALL, SignerType.Secp256k1
        );

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
        _assertErc20(false, address(sponsorERC20), __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
    }

    // Test ERC20_MODE with specific bundler full cycle
    function test_paymaster_7702_account_mode_1_check_bundler_eoa_signer() external {
        _assert(true, 0);
        _assertErc20(true, address(sponsorERC20), __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);

        bytes memory dataApprove =
            abi.encodeWithSelector(IERC20.approve.selector, address(paymaster), type(uint256).max);
        calls.push(_encodeCall(address(sponsorERC20), 0, dataApprove));
        calls.push(_encodeCall(random, 0.1 ether, hex""));

        bytes memory data = abi.encodeWithSelector(BaseAccount.executeBatch.selector, calls);

        (PackedUserOperation[] memory u,) = _getUserOp(
            __7702_ADDRESS_EOA, __7702_EOA, data, Sponsor_Type.ERC20, Allow_Bundlers.SPECIFIC, SignerType.Secp256k1
        );

        vm.prank(bundlers[0], bundlers[0]);
        entryPoint.handleOps(u, payable(bundlers[0]));
        _assert(false, 0.1 ether);
        _assertErc20(false, address(sponsorERC20), __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
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

    function _assert(ValidationData memory _data, bytes memory _context, bytes32 _userOpHash) internal view {
        assertEq(_data.aggregator, address(0), "Not same aggregator address");
        assertEq(_data.validUntil, type(uint48).max, "Not same aggregator validUntil");
        assertEq(_data.validAfter, 0, "Not same aggregator validAfter");
        assertNotEq(_context, hex"", "Not same aggregator context");

        ERC20PostOpContext memory postOpContext = abi.decode(_context, (ERC20PostOpContext));
        assertEq(postOpContext.sender, __7702_ADDRESS_EOA, "Not same sender");
        assertEq(postOpContext.token, address(sponsorERC20), "Not same token");
        assertEq(postOpContext.treasury, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, "Not same treasury");
        assertEq(postOpContext.exchangeRate, uint256(1e18), "Not same exchangeRate");
        assertEq(postOpContext.postOpGas, uint128(GAS), "Not same postOpGas");
        assertEq(postOpContext.userOpHash, _userOpHash, "Not same userOpHash");
        assertEq(postOpContext.maxFeePerGas, 0, "Not same maxFeePerGas");
        assertEq(postOpContext.maxPriorityFeePerGas, 0, "Not same maxPriorityFeePerGas");
        assertEq(postOpContext.recipient, address(0), "Not same recipient");
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

    function _assertErc20(bool _isBefore, address _erc20, address _reciever) internal {
        if (_isBefore) {
            balanceBeforeErc20 = IERC20(_erc20).balanceOf(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
            assertEq(balanceBeforeErc20, 0, "Not same balance");
        } else {
            balanceAfterErc20 = IERC20(_erc20).balanceOf(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
            assertNotEq(balanceAfterErc20, 0, "Not same balance");
        }
    }
}

/**
 * @dev paymasterAndData for mode 1:
 *
 *  [0x0000000000000000000000000000000000000000][0x00000000000000000000000000000000][0x00000000000000000000000000000000][0x00][0x000000000000][0x000000000000]
 *  |        paymaster address 20 bytes        |     verification gas 16 bytes     |        postop gas 16 bytes        |  aB |   validUntil  |   validAfter  |
 *
 *  [0x0000000000000000000000000000000000000000][0x00000000000000000000000000000000][0x0000000000000000000000000000000000000000000000000000000000000000]
 *  |            token address 20 bytes        |        postop gas 16 bytes        |                       exchangeRate 32 bytes                       |
 *
 *  [0x00000000000000000000000000000000][0x0000000000000000000000000000000000000000][0x00000000000000000000000000000000][0x00000000000000000000000000000000]
 *  |       paymasterVGL 16 bytes      |        treasury address 20 bytes          |          preFund 16 bytes         |        constantFee 16 bytes       |
 *
 *  [0x0000000000000000000000000000000000000000]
 *  |         recipient address 20 bytes       |
 *
 *  [0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000/00]
 *  |                                                       signature   64 or 65 bytes                                                    |
 */