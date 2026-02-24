// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

interface IManagerAccessControl {
    function MANAGER_ROLE() external view returns (bytes32);

    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
}
