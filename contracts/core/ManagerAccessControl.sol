// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Errors } from "../type/Errors.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

abstract contract ManagerAccessControl is AccessControl {
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    modifier onlyAdminOrManager() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && !hasRole(ManagerAccessControl.MANAGER_ROLE, msg.sender)) {
            revert Errors.AccessControlUnauthorizedAccount(msg.sender, ManagerAccessControl.MANAGER_ROLE);
        }
        _;
    }
}
