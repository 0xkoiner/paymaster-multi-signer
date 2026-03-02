// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Helpers } from "../helpers/Helpers.t.sol";

contract AccountDeployment is Helpers {
    function setUp() public override {
        super.setUp();
    }

    // Test upgrade EOA to 7702 account
    function test_upgrade_eoa_7702() external {
        _etch7702(__7702_ADDRESS_EOA, address(simple7702Account));

        bytes memory code = __7702_ADDRESS_EOA.code;
        assertEq(code, abi.encodePacked(bytes3(0xef0100), address(simple7702Account)), "Not same designator");
    }
}