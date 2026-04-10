// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Storage } from "./Storage.sol";
import { Errors } from "../type/Errors.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { KeysManager } from "./KeysManager.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";

abstract contract ManagerAccessControl is Storage {
    using KeyLib for *;
    using LibBytes for LibBytes.BytesStorage;

    modifier onlySuperAdminOrAdminKeyOrEp() {
        bytes32 hash = msg.sender.hash();
        bool hasKey = keyStorage[hash].length() != 0;

        if (
            !(hasKey && keyStorage[hash]._isSuperAdmin()) && !(hasKey && keyStorage[hash]._isAdmin())
                && msg.sender != address(entryPoint) && msg.sender != address(this)
        ) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }
    modifier onlySuperAdminKeyOrEp() {
        bytes32 hash = msg.sender.hash();
        bool hasKey = keyStorage[hash].length() != 0;

        if (
            !(hasKey && keyStorage[hash]._isSuperAdmin()) && msg.sender != address(entryPoint)
                && msg.sender != address(this)
        ) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }
}
