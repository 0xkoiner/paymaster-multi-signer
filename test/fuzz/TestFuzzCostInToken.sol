// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { PaymasterLib } from "../../contracts/library/PaymasterLib.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestFuzzCostInToken is Helpers {
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
    //    _getCostInToken — no revert on bounded inputs
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_getCostInToken_no_revert(
        uint96 _actualGasCost,
        uint64 _postOpGas,
        uint64 _actualUserOpFeePerGas,
        uint96 _exchangeRate
    )
        external
        pure
    {
        // Bounded: (uint96 + uint64*uint64) * uint96 fits in uint256
        PaymasterLib._getCostInToken(_actualGasCost, _postOpGas, _actualUserOpFeePerGas, _exchangeRate);
    }

    // ------------------------------------------------------------------------------------
    //
    //    _getCostInToken — zero exchange rate returns zero
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_getCostInToken_zero_rate(
        uint128 _actualGasCost,
        uint64 _postOpGas,
        uint64 _actualUserOpFeePerGas
    )
        external
        pure
    {
        uint256 result = PaymasterLib._getCostInToken(_actualGasCost, _postOpGas, _actualUserOpFeePerGas, 0);
        assertEq(result, 0, "Zero exchange rate should return zero cost");
    }

    // ------------------------------------------------------------------------------------
    //
    //    _getCostInToken — 1e18 exchange rate returns gas cost
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_getCostInToken_1e18_rate(
        uint128 _actualGasCost,
        uint64 _postOpGas,
        uint64 _feePerGas
    )
        external
        pure
    {
        uint256 result = PaymasterLib._getCostInToken(_actualGasCost, _postOpGas, _feePerGas, 1e18);
        uint256 expected = uint256(_actualGasCost) + uint256(_postOpGas) * uint256(_feePerGas);
        assertEq(result, expected, "1e18 rate should return exact gas cost in token");
    }

    // ------------------------------------------------------------------------------------
    //
    //    _getCostInToken — monotonic with exchange rate
    //
    // ------------------------------------------------------------------------------------

    function test_fuzz_getCostInToken_monotonic(
        uint96 _actualGasCost,
        uint64 _postOpGas,
        uint64 _feePerGas,
        uint96 _rateA,
        uint96 _rateB
    )
        external
        pure
    {
        vm.assume(_rateA <= _rateB);

        uint256 costA = PaymasterLib._getCostInToken(_actualGasCost, _postOpGas, _feePerGas, _rateA);
        uint256 costB = PaymasterLib._getCostInToken(_actualGasCost, _postOpGas, _feePerGas, _rateB);
        assertTrue(costA <= costB, "Higher exchange rate should produce higher or equal cost");
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
