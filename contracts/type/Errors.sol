// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @title Errors
/// @dev Custom errors used across the paymaster contracts.
library Errors {
    /// @dev Attempted to remove a superAdmin or admin key via `removeSigner`.
    error KillSwitch();
    /// @dev A required address parameter was `address(0)`.
    error AddressZero();
    /// @dev The key is already registered in storage.
    error KeyAuthorized();
    /// @dev The ERC-20 pre-fund exceeds the estimated token cost.
    error PreFundTooHigh();
    /// @dev No key exists for the given hash.
    error KeyDoesNotExist();
    /// @dev The userOp sender has no deployed code (not a contract/EIP-7702 delegate).
    error SenderHasNoCode();
    /// @dev The recipient address in the ERC-20 config is `address(0)` when flagged as present.
    error RecipientInvalid();
    /// @dev The sender's code does not start with the `0xef0100` EIP-7702 delegation prefix.
    error NotEIP7702Delegate();
    /// @dev The signer type byte exceeds the valid `SignerType` enum range.
    error IncorrectSignerType();
    /// @dev The ERC-20 exchange rate is zero.
    error ExchangeRateInvalid();
    /// @dev The key's role flags do not match the expected role for the operation.
    error IncorrectSignerRole();
    /// @dev `msg.sender` is not the bound EntryPoint contract.
    error SenderNotEntryPoint();
    /// @dev The ERC-20 token address in the paymaster config is `address(0)`.
    error TokenAddressInvalid();
    /// @dev The paymaster mode byte is neither verifying nor ERC-20.
    error PaymasterModeInvalid();
    /// @dev The paymaster config slice is shorter than the minimum required length.
    error PaymasterConfigLengthInvalid();
    /// @dev The raw `paymasterAndData` field is too short to contain a mode byte.
    error PaymasterAndDataLengthInvalid();
    /// @dev The signature length does not match the expected size for its signer type.
    error PaymasterSignatureLengthInvalid();
    /// @dev The `tx.origin` bundler is not on the allowlist and `allowAllBundlers` is false.
    error BundlerNotAllowed(address bundler);
    /// @dev A call inside `executeBatch` reverted at the given index.
    error ExecuteError(uint256 index, bytes error);
    /// @dev The caller does not hold the required key role for this function.
    error AccessControlUnauthorizedAccount(address account);
}
