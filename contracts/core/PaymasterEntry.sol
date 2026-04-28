/*
     _____________
    | _"_________ |     ███████████    █████████   █████ █████ ██████   ██████   █████████    █████████  ███████████ ██████████ ███████████
    ||.---------.||    ░░███░░░░░███  ███░░░░░███ ░░███ ░░███ ░░██████ ██████   ███░░░░░███  ███░░░░░███░█░░░███░░░█░░███░░░░░█░░███░░░░░███
    |||         |||     ░███    ░███ ░███    ░███  ░░███ ███   ░███░█████░███  ░███    ░███ ░███    ░░░ ░   ░███  ░  ░███  █ ░  ░███    ░███
    |||   GAS   |||     ░██████████  ░███████████   ░░█████    ░███░░███ ░███  ░███████████ ░░█████████     ░███     ░██████    ░██████████
    |||         |||     ░███░░░░░░   ░███░░░░░███    ░░███     ░███ ░░░  ░███  ░███░░░░░███  ░░░░░░░░███    ░███     ░███░░█    ░███░░░░░███
    ||'---------'/|     ░███         ░███    ░███     ░███     ░███      ░███  ░███    ░███  ███    ░███    ░███     ░███ ░   █ ░███    ░███
    | """"""""""` |     █████        █████   █████    █████    █████     █████ █████   █████░░█████████     █████    ██████████ █████   █████
    | ||  ^^^  () |     ░░░░░        ░░░░░   ░░░░░    ░░░░░    ░░░░░     ░░░░░ ░░░░░   ░░░░░  ░░░░░░░░░     ░░░░░    ░░░░░░░░░░ ░░░░░   ░░░░░
    |[  ]    ()   |
    | ||          |
    |     _ _     |                                            ░█▀▀░█▀▄░█▀▀░█░█░▀▀█░▀▀█░▀▀█
    |          :::|                                            ░█▀▀░█▀▄░█░░░░▀█░░▀▄░░▀▄░▄▀░
    |         .::'/                                            ░▀▀▀░▀░▀░▀▀▀░░░▀░▀▀░░▀▀░░▀░░
    '""""""""""""`
*/

// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { Paymaster } from "./Paymaster.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { IWebAuthnVerifier } from "../interface/IWebAuthnVerifier.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

/// @title Paymaster Multi-Signers
/// @author 0xkoiner
/// @notice Inspired by Pimlico and Solady Paymaster.
contract PaymasterEntry is Paymaster {
    using KeyLib for *;

    /// @notice Deploy the paymaster with an initial key set, EntryPoint binding, and bundler allowlist.
    /// @param _superAdmin      The superAdmin key (must pass `_isSuperAdmin()`).
    /// @param _admin           The admin key (must pass `_isAdmin()`).
    /// @param _signers         Initial signer keys (each must pass `_isSigner()`).
    /// @param _entryPoint      The ERC-4337 EntryPoint this paymaster is bound to (immutable, non-zero).
    /// @param _webAuthnVerifier The WebAuthn P256 verifier contract (immutable, non-zero).
    /// @param _allowedBundlers Addresses initially permitted to submit user operations (non-zero each).
    constructor(
        Key memory _superAdmin,
        Key memory _admin,
        Key[] memory _signers,
        IEntryPoint _entryPoint,
        IWebAuthnVerifier _webAuthnVerifier,
        address[] memory _allowedBundlers
    ) {
        if (!_superAdmin._isSuperAdmin()) revert();
        if (!_admin._isAdmin()) revert();

        _addKey(_superAdmin);
        _addKey(_admin);

        uint256 i = 0;
        for (i; i < _signers.length;) {
            if (!_signers[i]._isSigner()) revert();
            _addKey(_signers[i]);
            unchecked {
                ++i;
            }
        }

        for (i = 0; i < _allowedBundlers.length;) {
            if (_allowedBundlers[i] == address(0)) revert();
            isBundlerAllowed[_allowedBundlers[i]] = true;
            unchecked {
                ++i;
            }
        }

        if (address(_entryPoint) == address(0) || address(_webAuthnVerifier) == address(0)) {
            revert Errors.AddressZero();
        }
        entryPoint = _entryPoint;
        webAuthnVerifier = _webAuthnVerifier;
    }
}
