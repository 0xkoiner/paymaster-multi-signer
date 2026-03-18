// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

library Errors {
    error KillSwitch();
    error AddressZero();
    error KeyAuthorized();
    error PreFundTooHigh();
    error KeyDoesNotExist();
    error SenderHasNoCode();
    error RecipientInvalid();
    error NotEIP7702Delegate();
    error IncorrectSignerType();
    error ExchangeRateInvalid();
    error IncorrectSignerRole();
    error SenderNotEntryPoint();
    error TokenAddressInvalid();
    error PaymasterModeInvalid();
    error PaymasterConfigLengthInvalid();
    error PaymasterAndDataLengthInvalid();
    error PaymasterSignatureLengthInvalid();
    error BundlerNotAllowed(address bundler);
    error ExecuteError(uint256 index, bytes error);
    error AccessControlUnauthorizedAccount(address account);
}
