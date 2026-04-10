// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestFuzzPenaltyGasCost is Helpers {
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

    // ------------------------------------------------------------------------------------
    //
    //    _expectedPenaltyGasCost — no revert on valid inputs
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_expectedPenaltyGasCost_no_revert(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 _postOpGas,
        uint256 _preOpGasApproximation,
        uint256 _executionGasLimit
    )
        external
        view
    {
        // Guard: avoid division by zero
        vm.assume(_actualUserOpFeePerGas > 0);
        // Guard: avoid multiplication overflow in actualGas
        vm.assume(_actualGasCost / _actualUserOpFeePerGas <= type(uint256).max - _postOpGas);

        uint256 actualGas = _actualGasCost / _actualUserOpFeePerGas + _postOpGas;

        uint256 executionGasUsed = 0;
        if (actualGas > _preOpGasApproximation) {
            executionGasUsed = actualGas - _preOpGasApproximation;
        }

        uint256 unusedGas = 0;
        if (_executionGasLimit > executionGasUsed) {
            unusedGas = _executionGasLimit - executionGasUsed;
        }

        // Guard: avoid overflow in penalty * feePerGas
        vm.assume(unusedGas <= type(uint256).max / 10);
        uint256 expectedPenaltyGas = (unusedGas * 10) / 100;
        vm.assume(expectedPenaltyGas <= type(uint256).max / _actualUserOpFeePerGas);

        // Should not revert
        paymaster._expectedPenaltyGasCost(
            _actualGasCost, _actualUserOpFeePerGas, _postOpGas, _preOpGasApproximation, _executionGasLimit
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //    _expectedPenaltyGasCost — result is zero when no unused gas
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_expectedPenaltyGasCost_zero_when_fully_used(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 _postOpGas,
        uint256 _preOpGasApproximation
    )
        external
        view
    {
        vm.assume(_actualUserOpFeePerGas > 0);
        vm.assume(_actualGasCost / _actualUserOpFeePerGas <= type(uint256).max - _postOpGas);

        // executionGasLimit = 0 means no unused gas
        uint256 result = paymaster._expectedPenaltyGasCost(
            _actualGasCost, _actualUserOpFeePerGas, _postOpGas, _preOpGasApproximation, 0
        );

        assertEq(result, 0, "Penalty should be zero when executionGasLimit is zero");
    }

    // ------------------------------------------------------------------------------------
    //
    //    _expectedPenaltyGasCost — penalty proportional to unused gas
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_expectedPenaltyGasCost_proportional(uint128 _unusedGas, uint128 _feePerGas) external view {
        vm.assume(_feePerGas > 0);

        // Set up inputs so that executionGasUsed = 0, executionGasLimit = _unusedGas
        // actualGasCost = 0, postOpGas = 0 → actualGas = 0
        // preOpGasApproximation = 0 → executionGasUsed = 0
        uint256 result = paymaster._expectedPenaltyGasCost(
            0, // actualGasCost
            _feePerGas,
            0, // postOpGas
            0, // preOpGas
            _unusedGas // executionGasLimit
        );

        uint256 expected = (uint256(_unusedGas) * 10 / 100) * uint256(_feePerGas);
        assertEq(result, expected, "Penalty should be 10% of unused gas * feePerGas");
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
