// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { UserOperationLib } from "@account-abstraction/contracts/core/UserOperationLib.sol";

/// @dev Cryptographic key type used by a signer.
enum SignerType {
    /// @dev NIST P-256 (secp256r1) key.
    P256,
    /// @dev WebAuthn-wrapped P-256 key (passkey).
    WebAuthnP256,
    /// @dev Ethereum secp256k1 EOA key.
    Secp256k1
}

/// @dev Outcome mode passed to `postOp` by the EntryPoint.
enum PostOpMode {
    /// @dev The user operation executed successfully.
    opSucceeded,
    /// @dev The user operation's execution reverted.
    opReverted,
    /// @dev The first `postOp` call reverted; this is the retry.
    postOpReverted
}

/// @dev On-chain representation of an authorized key (superAdmin, admin, or signer).
struct Key {
    /// @dev Unix timestamp after which the key is no longer valid. `type(uint40).max` for superAdmin (never expires).
    uint40 expiry;
    /// @dev The cryptographic key type.
    SignerType keyType;
    /// @dev Whether this key has the superAdmin role.
    bool isSuperAdmin;
    /// @dev Whether this key has the admin role.
    bool isAdmin;
    /// @dev ABI-encoded public key: `abi.encode(address)` for Secp256k1, `abi.encode(qx, qy)` for P256/WebAuthn.
    bytes publicKey;
}

/// @dev A single call within an `executeBatch` batch.
struct Call {
    /// @dev Target contract address.
    address target;
    /// @dev ETH value to forward with the call.
    uint256 value;
    /// @dev Calldata to pass to the target.
    bytes data;
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
    /// @dev The signerType.
    uint8 signerType;
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

/// @title Types
/// @dev Constants used across the paymaster contracts.
library Types {
    /// @dev ERC-4337 unused-gas penalty percentage (10%).
    uint256 constant PENALTY_PERCENT = 10;
    /// @dev Byte offset where paymaster-specific data begins in `paymasterAndData`.
    uint256 constant PAYMASTER_DATA_OFFSET = UserOperationLib.PAYMASTER_DATA_OFFSET;
    /// @dev Byte offset of the paymaster validation gas limit in `paymasterAndData`.
    uint256 constant PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET;

    /// @dev Mode byte value for verifying (gas-only) sponsorship.
    uint8 constant VERIFYING_MODE = 0;
    /// @dev Mode byte value for ERC-20 token-paid sponsorship.
    uint8 constant ERC20_MODE = 1;
    /// @dev Length of the combined mode + allowAllBundlers byte.
    uint8 constant MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH = 1;
    /// @dev Minimum byte length of the ERC-20 paymaster config (excluding optional fields).
    uint8 constant ERC20_PAYMASTER_DATA_LENGTH = 117;
    /// @dev Byte length of the verifying mode paymaster config (validUntil + validAfter).
    uint8 constant VERIFYING_PAYMASTER_DATA_LENGTH = 12;

    /// @dev Function selector for `executeBatch(Call[])`.
    bytes4 constant EXECUTE_BATCH_SEL = 0x34fcd5be;
    /// @dev Function selector for `approve(address,uint256)`.
    bytes4 constant APPROVE_SEL = 0x095ea7b3;
}
