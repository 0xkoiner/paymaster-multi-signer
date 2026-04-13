// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { PostOpMode, SignerType } from "../../contracts/type/Types.sol";
import { IBasePaymaster } from "./IBasePaymaster.sol";
import { IWebAuthnVerifier } from "./IWebAuthnVerifier.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

interface IPaymaster is IBasePaymaster {
    // ------------------------------------------------------------------------------------
    //
    //                              Storage Getters
    //
    // ------------------------------------------------------------------------------------

    /// @notice The immutable ERC-4337 EntryPoint this paymaster is bound to.
    function entryPoint() external view returns (IEntryPoint);

    /// @notice The immutable WebAuthn P256 signature verifier contract.
    function webAuthnVerifier() external view returns (IWebAuthnVerifier);

    /// @notice Whether an address is registered as a valid signer.
    /// @param account The address to check.
    function signers(address account) external view returns (bool isValidSigner);

    /// @notice Whether a bundler address is allowed to submit user operations.
    /// @param bundler The bundler address to check.
    function isBundlerAllowed(address bundler) external view returns (bool allowed);

    // ------------------------------------------------------------------------------------
    //
    //                              Gas Penalty Calculation
    //
    // ------------------------------------------------------------------------------------

    /// @notice Compute the expected penalty gas cost for unused execution gas.
    ///         Per ERC-4337, a 10% penalty is applied to unused execution gas
    ///         to discourage inflated gas limits.
    /// @param _actualGasCost          Total gas cost in wei reported by the EntryPoint.
    /// @param _actualUserOpFeePerGas  Actual fee per gas unit for this user operation.
    /// @param _postOpGas              Gas overhead reserved for the postOp transfer call.
    /// @param _preOpGasApproximation  Estimated gas consumed before execution (verification + preOp).
    /// @param _executionGasLimit      Total allowed execution gas (callGasLimit + postOpGasLimit).
    /// @return The penalty cost in wei to add to the actual gas cost.
    function _expectedPenaltyGasCost(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 _postOpGas,
        uint256 _preOpGasApproximation,
        uint256 _executionGasLimit
    )
        external
        pure
        returns (uint256);

    // ------------------------------------------------------------------------------------
    //
    //                          Paymaster Validation & Settlement
    //
    // ------------------------------------------------------------------------------------

    /// @notice Compute the hash that a paymaster signer must sign to authorize a user operation.
    ///         Includes the userOp fields (sender, nonce, gas, callData, paymasterAndData),
    ///         the signer type, the chain id, and an EIP-7702 init-code override when applicable.
    /// @param _mode       Paymaster mode — `0` for verifying, `1` for ERC-20.
    /// @param _userOp     The packed user operation whose fields are hashed.
    /// @param _signerType The signer key type used to produce the paymaster signature.
    /// @return The EIP-191 signed message hash the signer must sign.
    function getHash(
        uint8 _mode,
        PackedUserOperation calldata _userOp,
        SignerType _signerType
    )
        external
        view
        returns (bytes32);

    /// @notice Validate a user operation on behalf of the paymaster.
    ///         Called by the EntryPoint during the validation phase.
    ///         Verifies the paymaster signature, enforces bundler allowlists,
    ///         and optionally charges an ERC-20 pre-fund from the sender.
    /// @param _userOp         The packed user operation to validate.
    /// @param _userOpHash     Hash of the user operation provided by the EntryPoint.
    /// @param _requiredPreFund Minimum ETH the paymaster must have deposited to cover gas.
    /// @return context        ABI-encoded context passed to `postOp` (empty for verifying mode).
    /// @return validationData Packed result: signature validity, validUntil, and validAfter.
    function validatePaymasterUserOp(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        external
        returns (bytes memory context, uint256 validationData);

    /// @notice Settle the ERC-20 token payment after a user operation has executed.
    ///         Called by the EntryPoint. Computes the actual gas cost in tokens,
    ///         transfers the difference between the pre-funded amount and the actual cost,
    ///         and forwards any surplus to the configured recipient.
    /// @param _mode                  Indicates whether the operation succeeded, reverted, or postOp reverted.
    /// @param _context               ABI-encoded `ERC20PostOpContext` returned by `validatePaymasterUserOp`.
    /// @param _actualGasCost         Actual gas cost in wei charged by the EntryPoint.
    /// @param _actualUserOpFeePerGas Actual fee per gas unit for this user operation.
    function postOp(
        PostOpMode _mode,
        bytes calldata _context,
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas
    )
        external;
}
