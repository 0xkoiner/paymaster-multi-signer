// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Storage } from "./Storage.sol";
import { Errors } from "../type/Errors.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { KeysManager } from "./KeysManager.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

abstract contract ManagerAccessControl is AccessControl, Storage {
    using KeyLib for *;
    using LibBytes for LibBytes.BytesStorage;

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    modifier onlyAdminOrManager() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && !hasRole(ManagerAccessControl.MANAGER_ROLE, msg.sender)) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }

    modifier onlySuperAdminOrAdminKeyOrEp() {
        bytes32 hash = msg.sender.hash();
        bool hasKey = keyStorage[hash].length() != 0;

        if (
            !(hasKey && keyStorage[hash]._isSuperAdmin()) && !(hasKey && keyStorage[hash]._isAdmin())
                && msg.sender != address(entryPoint)
        ) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }
    modifier onlySuperAdminKeyOrEp() {
        if (!keyStorage[msg.sender.hash()]._isSuperAdmin() && msg.sender == address(entryPoint)) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }
}
