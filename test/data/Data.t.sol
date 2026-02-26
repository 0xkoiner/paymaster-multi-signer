// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Test } from "../../lib/forge-std/src/Test.sol";
import { KeysManager } from "../../contracts/core/KeysManager.sol";

contract Data is Test {
    KeysManager internal keysManager;

    function setUp() public virtual {
        keysManager = new KeysManager();
    }
}
