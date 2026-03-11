// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { AAHelpers } from "./AAHelpers.t.sol";
import { Constants } from "../data/Constants.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";

contract Helpers is AAHelpers {
    function _deal(address _address, uint256 _amount) internal {
        deal(_address, _amount);
    }

    function _mint(address _to, uint256 _amount, bool _isSponsoreErc20) internal {
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        _isSponsoreErc20 ? sponsorERC20.mint(_to, _amount) : sponsorERC20.mint(_to, _amount);
    }
}
