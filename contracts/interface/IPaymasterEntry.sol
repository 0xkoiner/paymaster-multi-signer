// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { IPaymaster } from "./IPaymaster.sol";
import { IKeysManager } from "./IKeysManager.sol";
import { IWebAuthnVerifier } from "./IWebAuthnVerifier.sol";

interface IPaymasterEntry is IWebAuthnVerifier, IKeysManager, IPaymaster { }
