// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

library Constants {
    // ------------------------------------------------------------------------------------
    //
    //                                  AA Address Standards
    //
    // ------------------------------------------------------------------------------------

    // Canonical address of EPv9
    address internal constant EP_V9_ADDRESS = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    // ------------------------------------------------------------------------------------
    //
    //                                   Constants
    //
    // ------------------------------------------------------------------------------------

    // ETH value to transfer
    uint256 internal constant ETH_1 = 1 ether;

    // Fixed Data Mar 02 2048
    uint40 internal constant EXPIRY = 2_466_751_799;
}
