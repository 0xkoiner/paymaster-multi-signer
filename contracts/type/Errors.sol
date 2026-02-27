// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

library Errors {
    error KillSwitch();
    error KeyAuthorized();
    error PreFundTooHigh();
    error KeyDoesNotExist();
    error SenderHasNoCode();
    error RecipientInvalid();
    error NotEIP7702Delegate();
    error ExchangeRateInvalid();
    error IncorrectSignerRole();
    error SenderNotEntryPoint();
    error TokenAddressInvalid();
    error PaymasterModeInvalid();
    error PaymasterConfigLengthInvalid();
    error PaymasterAndDataLengthInvalid();
    error PaymasterSignatureLengthInvalid();
    error BundlerNotAllowed(address bundler);
    error AccessControlUnauthorizedAccount(address account);
}
