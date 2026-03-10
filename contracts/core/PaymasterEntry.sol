// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";
import { Errors } from "../type/Errors.sol";
import { Paymaster } from "./Paymaster.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { IWebAuthnVerifier } from "../interface/IWebAuthnVerifier.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract PaymasterEntry is Paymaster {
    using KeyLib for *;

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

        authorize(_superAdmin);
        authorize(_admin);

        uint256 i = 0;
        for (i; i < _signers.length;) {
            if (!_signers[i]._isSigner()) revert();
            authorize(_signers[i]);
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
