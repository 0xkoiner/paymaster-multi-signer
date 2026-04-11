/*
 * ═══════════════════════════════════════════════════════════════════════════════
 *  PAYMASTER ARITHMETIC SPECIFICATION
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Verifies: PE-7, PE-8, PE-9 from VERIFICATION_PLAN.md
 *
 *  These are pure function properties — no state, no external calls.
 *  They verify mathematical correctness of gas cost calculations.
 *
 *  WHY these properties matter:
 *    Arithmetic errors in gas cost calculations can lead to:
 *    - Users being overcharged or undercharged for gas
 *    - Division by zero causing postOp to revert (locking user funds)
 *    - Overflow causing valid operations to fail
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ─── Methods Block ───────────────────────────────────────────────────────────

methods {
    // ── Arithmetic harness wrappers ──
    function getCostInTokenHarness(uint256, uint256, uint256, uint256)
        external returns (uint256) envfree;

    // ── Direct contract function (public pure in Validations.sol) ──
    function _expectedPenaltyGasCost(uint256, uint256, uint128, uint256, uint256)
        external returns (uint256) envfree;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PE-7: _getCostInToken Formula Correctness
//
//  PaymasterLib._getCostInToken computes:
//    ((actualGasCost + (postOpGas * feePerGas)) * exchangeRate) / 1e18
//
//  We verify this formula holds exactly (no rounding error beyond Solidity's
//  integer division) by comparing against mathint arithmetic.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice PE-7: getCostInToken returns the correct value when no overflow occurs.
rule PE7_getCostInToken_formula {
    uint256 actualGasCost;
    uint256 postOpGas;
    uint256 feePerGas;
    uint256 exchangeRate;

    uint256 result = getCostInTokenHarness@withrevert(
        actualGasCost, postOpGas, feePerGas, exchangeRate
    );

    // Expected computation in arbitrary-precision mathint
    mathint gasCostTotal = to_mathint(actualGasCost)
                         + to_mathint(postOpGas) * to_mathint(feePerGas);
    mathint expected = (gasCostTotal * to_mathint(exchangeRate)) / (10 ^ 18);

    // If the function didn't revert (no overflow), result must match the formula
    assert !lastReverted => to_mathint(result) == expected,
        "PE-7: _getCostInToken must match ((gasCost + postOpGas*fee) * rate) / 1e18";
}

/// @notice PE-7: getCostInToken reverts on overflow (Solidity 0.8 checked math).
///         We prove that overflow IS possible with large inputs.
rule PE7_getCostInToken_canOverflow {
    uint256 actualGasCost;
    uint256 postOpGas;
    uint256 feePerGas;
    uint256 exchangeRate;

    // Force large values that cause overflow
    require to_mathint(actualGasCost) > 0;
    require to_mathint(exchangeRate) > 10 ^ 18;
    require to_mathint(postOpGas) * to_mathint(feePerGas) > to_mathint(max_uint256) / 2;

    getCostInTokenHarness@withrevert(actualGasCost, postOpGas, feePerGas, exchangeRate);

    satisfy lastReverted,
        "PE-7: _getCostInToken can revert on overflow with large inputs";
}

/// @notice PE-7 SANITY: getCostInToken can succeed for reasonable inputs.
rule PE7_getCostInToken_sanity {
    uint256 actualGasCost;
    uint256 postOpGas;
    uint256 feePerGas;
    uint256 exchangeRate;

    getCostInTokenHarness@withrevert(actualGasCost, postOpGas, feePerGas, exchangeRate);

    satisfy !lastReverted,
        "PE-7 sanity: _getCostInToken can produce a valid result";
}

/// @notice PE-7: getCostInToken returns 0 when exchangeRate is 0.
///         This is mathematically correct (anything * 0 / 1e18 = 0) but may
///         indicate a configuration error. The contract validates exchangeRate != 0
///         at parse time, but the library function itself doesn't.
rule PE7_getCostInToken_zeroExchangeRate {
    uint256 actualGasCost;
    uint256 postOpGas;
    uint256 feePerGas;

    uint256 result = getCostInTokenHarness@withrevert(
        actualGasCost, postOpGas, feePerGas, 0
    );

    assert !lastReverted => result == 0,
        "PE-7: _getCostInToken with exchangeRate=0 must return 0";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PE-8: Division by Zero in _expectedPenaltyGasCost
//
//  _expectedPenaltyGasCost performs: _actualGasCost / _actualUserOpFeePerGas
//  When _actualUserOpFeePerGas == 0, this is division by zero → revert.
//
//  The EntryPoint should never pass 0, but the contract has NO defensive check.
//  If this reverts, the entire postOp fails, potentially locking user funds.
//
//  Severity: MEDIUM (depends on EntryPoint guarantees)
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice PE-8 BUG CONFIRMATION: Division by zero when feePerGas == 0.
rule PE8_divisionByZero_reverts {
    uint256 actualGasCost;
    uint128 postOpGas;
    uint256 preOpGasApprox;
    uint256 execGasLimit;

    // Force the division-by-zero condition
    _expectedPenaltyGasCost@withrevert(
        actualGasCost,
        0,              // actualUserOpFeePerGas = 0 → division by zero
        postOpGas,
        preOpGasApprox,
        execGasLimit
    );

    assert lastReverted,
        "PE-8: _expectedPenaltyGasCost MUST revert when actualUserOpFeePerGas == 0";
}

/// @notice PE-8 SANITY: Function succeeds with non-zero feePerGas.
rule PE8_nonZero_succeeds {
    uint256 actualGasCost;
    uint256 feePerGas;
    uint128 postOpGas;
    uint256 preOpGasApprox;
    uint256 execGasLimit;

    require feePerGas > 0;

    _expectedPenaltyGasCost@withrevert(
        actualGasCost, feePerGas, postOpGas, preOpGasApprox, execGasLimit
    );

    satisfy !lastReverted,
        "PE-8 sanity: _expectedPenaltyGasCost can succeed with non-zero feePerGas";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PE-9: _expectedPenaltyGasCost Boundary Properties
//
//  The function computes:
//    actualGas = actualGasCost / feePerGas + postOpGas
//    executionGasUsed = max(0, actualGas - preOpGasApprox)
//    expectedPenalty = max(0, (execGasLimit - executionGasUsed) * 10 / 100)
//    result = expectedPenalty * feePerGas
//
//  Properties:
//    1. Result is always 0 when execGasLimit <= executionGasUsed
//    2. Result is always 0 when feePerGas == 0 (but this reverts — see PE-8)
//    3. Result is non-negative (by construction)
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice PE-9: When actualGas >= preOpGasApprox + execGasLimit,
///         the penalty is zero (all gas was used, nothing to penalize).
rule PE9_noPenaltyWhenAllGasUsed {
    uint256 actualGasCost;
    uint256 feePerGas;
    uint128 postOpGas;
    uint256 preOpGasApprox;
    uint256 execGasLimit;

    require feePerGas > 0;

    // Condition: actualGas >= preOpGasApprox + execGasLimit
    // actualGas = actualGasCost / feePerGas + postOpGas
    mathint actualGas = to_mathint(actualGasCost) / to_mathint(feePerGas)
                      + to_mathint(postOpGas);
    mathint executionGasUsed = actualGas > to_mathint(preOpGasApprox)
                             ? actualGas - to_mathint(preOpGasApprox)
                             : 0;

    // All execution gas was consumed or exceeded
    require executionGasUsed >= to_mathint(execGasLimit);

    uint256 result = _expectedPenaltyGasCost@withrevert(
        actualGasCost, feePerGas, postOpGas, preOpGasApprox, execGasLimit
    );

    assert !lastReverted => result == 0,
        "PE-9: No penalty when all execution gas was consumed";
}

/// @notice PE-9: Penalty gas cost is always a multiple of PENALTY_PERCENT (10).
///         The result = ((gasLimit - gasUsed) * 10 / 100) * feePerGas
///         Due to integer division, this is always <= 10% of unused gas cost.
rule PE9_penaltyAtMostTenPercent {
    uint256 actualGasCost;
    uint256 feePerGas;
    uint128 postOpGas;
    uint256 preOpGasApprox;
    uint256 execGasLimit;

    require feePerGas > 0;

    uint256 result = _expectedPenaltyGasCost@withrevert(
        actualGasCost, feePerGas, postOpGas, preOpGasApprox, execGasLimit
    );

    // The maximum unused gas cost is execGasLimit * feePerGas
    // Penalty should be at most 10% of that
    mathint maxPenalty = (to_mathint(execGasLimit) * to_mathint(feePerGas) * 10) / 100;

    assert !lastReverted => to_mathint(result) <= maxPenalty,
        "PE-9: Penalty must be at most 10% of maximum gas cost";
}

/// @notice PE-9: Deterministic — same inputs always produce same output.
rule PE9_deterministic {
    uint256 actualGasCost;
    uint256 feePerGas;
    uint128 postOpGas;
    uint256 preOpGasApprox;
    uint256 execGasLimit;

    require feePerGas > 0;

    uint256 result1 = _expectedPenaltyGasCost(
        actualGasCost, feePerGas, postOpGas, preOpGasApprox, execGasLimit
    );
    uint256 result2 = _expectedPenaltyGasCost(
        actualGasCost, feePerGas, postOpGas, preOpGasApprox, execGasLimit
    );

    assert result1 == result2,
        "PE-9: _expectedPenaltyGasCost must be deterministic";
}
