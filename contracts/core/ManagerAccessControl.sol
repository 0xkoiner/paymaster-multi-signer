// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Storage } from "./Storage.sol";
import { Errors } from "../type/Errors.sol";
import { KeyLib } from "../library/KeyLib.sol";
import { KeysManager } from "./KeysManager.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

abstract contract ManagerAccessControl is AccessControl, Storage {
    using KeyLib for *;

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    modifier onlyAdminOrManager() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && !hasRole(ManagerAccessControl.MANAGER_ROLE, msg.sender)) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }

    modifier onlySuperAdminOrAdminKey() {
        if (!keyStorage[msg.sender.hash()]._isSuperAdmin() && !keyStorage[msg.sender.hash()]._isAdmin()) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }
    modifier onlySuperAdminKey() {
        if (!keyStorage[msg.sender.hash()]._isSuperAdmin()) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender);
        }
        _;
    }
}
