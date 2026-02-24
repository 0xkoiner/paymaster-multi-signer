// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Storage } from "./Storage.sol";
import { Errors } from "../type/Errors.sol";

contract BasePaymaster is Storage {
    function _requireFromEntryPoint() internal view virtual {
        require(msg.sender == address(entryPoint), Errors.SenderNotEntryPoint());
    }
}
