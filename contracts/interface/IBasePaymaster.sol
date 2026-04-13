// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Call } from "../type/Types.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

interface IBasePaymaster {
    /// @notice Validate a user operation as an ERC-4337 account.
    /// @param userOp           The packed user operation to validate.
    /// @param userOpHash       Hash of the user operation.
    /// @param missingAccountFunds Minimum ETH to send to the EntryPoint to cover gas.
    /// @return validationData  Packed signature validation result and time-range.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        returns (uint256 validationData);

    /// @notice Deposit ETH into the EntryPoint on behalf of this contract.
    function deposit() external payable;

    /// @notice Withdraw ETH from the EntryPoint deposit.
    /// @param _withdrawAddress Address to receive the withdrawn ETH.
    /// @param _amount          Amount of ETH to withdraw.
    function withdrawTo(address payable _withdrawAddress, uint256 _amount) external;

    /// @notice Stake ETH in the EntryPoint.
    /// @param _unstakeDelaySec Minimum delay (seconds) before the stake can be withdrawn.
    function addStake(uint32 _unstakeDelaySec) external payable;

    /// @notice Return the current EntryPoint deposit balance for this contract.
    function getDeposit() external view returns (uint256);

    /// @notice Begin unlocking the staked ETH in the EntryPoint.
    function unlockStake() external;

    /// @notice Withdraw previously unlocked stake from the EntryPoint.
    /// @param _withdrawAddress Address to receive the withdrawn stake.
    function withdrawStake(address payable _withdrawAddress) external;

    /// @notice Execute a batch of calls from this contract via the EntryPoint.
    /// @param calls Array of calls (target, value, data) to execute sequentially.
    function executeBatch(Call[] calldata calls) external;
}
