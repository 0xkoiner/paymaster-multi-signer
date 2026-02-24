// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { UserOperationLib } from "@account-abstraction/contracts/core/UserOperationLib.sol";

enum PostOpMode {
    opSucceeded,
    opReverted,
    postOpReverted
}

/// @notice Hold all configs needed in ERC-20 mode.
struct ERC20PaymasterData {
    /// @dev The treasury address where the tokens will be sent to.
    address treasury;
    /// @dev Timestamp until which the sponsorship is valid.
    uint48 validUntil;
    /// @dev Timestamp after which the sponsorship is valid.
    uint48 validAfter;
    /// @dev The gas overhead of calling transferFrom during the postOp.
    uint128 postOpGas;
    /// @dev ERC-20 token that the sender will pay with.
    address token;
    /// @dev The exchange rate of the ERC-20 token during sponsorship.
    uint256 exchangeRate;
    /// @dev The paymaster signature.
    bytes signature;
    /// @dev The paymasterValidationGasLimit to be used in the postOp.
    uint128 paymasterValidationGasLimit;
    /// @dev The preFund of the userOperation.
    uint256 preFundInToken;
    /// @dev A constant fee that is added to the userOp's gas cost.
    uint128 constantFee;
    /// @dev The recipient of the tokens.
    address recipient;
}

/// @notice Holds all context needed during the EntryPoint's postOp call.
struct ERC20PostOpContext {
    /// @dev The userOperation sender.
    address sender;
    /// @dev The token used to pay for gas sponsorship.
    address token;
    /// @dev The treasury address where the tokens will be sent to.
    address treasury;
    /// @dev The exchange rate between the token and the chain's native currency.
    uint256 exchangeRate;
    /// @dev The gas overhead when performing the transferFrom call.
    uint128 postOpGas;
    /// @dev The userOperation hash.
    bytes32 userOpHash;
    /// @dev The userOperation's maxFeePerGas (v0.6 only)
    uint256 maxFeePerGas;
    /// @dev The userOperation's maxPriorityFeePerGas (v0.6 only)
    uint256 maxPriorityFeePerGas;
    /// @dev The pre fund of the userOperation.
    uint256 preFund;
    /// @dev The pre fund of the userOperation that was charged.
    uint256 preFundCharged;
    /// @dev The total allowed execution gas limit, i.e the sum of the callGasLimit and postOpGasLimit.
    uint256 executionGasLimit;
    /// @dev Estimate of the gas used before the userOp is executed.
    uint256 preOpGasApproximation;
    /// @dev A constant fee that is added to the userOp's gas cost.
    uint128 constantFee;
    /// @dev The recipient of the tokens.
    address recipient;
}

library Types {
    uint256 constant PENALTY_PERCENT = 10;
    uint256 constant PAYMASTER_DATA_OFFSET = UserOperationLib.PAYMASTER_DATA_OFFSET;
    uint256 constant PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET;

    uint8 constant VERIFYING_MODE = 0;
    uint8 constant ERC20_MODE = 1;
    uint8 constant MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH = 1;
    uint8 constant ERC20_PAYMASTER_DATA_LENGTH = 117;
    uint8 constant VERIFYING_PAYMASTER_DATA_LENGTH = 12;
}
