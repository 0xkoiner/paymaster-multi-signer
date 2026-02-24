// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

library Errors {
    error PreFundTooHigh();
    error SenderHasNoCode();
    error NotEIP7702Delegate();
    error SenderNotEntryPoint();
    error PaymasterModeInvalid();
    error BundlerNotAllowed(address bundler);
}
