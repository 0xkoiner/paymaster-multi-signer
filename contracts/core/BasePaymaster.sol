// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Errors } from "../type/Errors.sol";
import { MultiSigner } from "./MultiSigner.sol";

abstract contract BasePaymaster is MultiSigner {
    function deposit() public payable {
        entryPoint.depositTo{ value: msg.value }(address(this));
    }

    function withdrawTo(address payable _withdrawAddress, uint256 _amount) public onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint.withdrawTo(_withdrawAddress, _amount);
    }

    function addStake(uint32 _unstakeDelaySec) external payable onlyAdminOrManager {
        entryPoint.addStake{ value: msg.value }(_unstakeDelaySec);
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    function unlockStake() external onlyAdminOrManager {
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable _withdrawAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint.withdrawStake(_withdrawAddress);
    }

    function _requireFromEntryPoint() internal view virtual {
        require(msg.sender == address(entryPoint), Errors.SenderNotEntryPoint());
    }
}
