// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Data } from "../data/Data.t.sol";
import { Constants } from "../data/Constants.sol";
import { IPaymaster } from "../../contracts/interface/IPaymaster.sol";
import { SignatureCheckerLib } from "lib/solady-v0.1.26/src/utils/SignatureCheckerLib.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

contract AAHelpers is Data {
    // ------------------------------------------------------------------------------------
    //
    //                                       Enum/Structs
    //
    // ------------------------------------------------------------------------------------

    // Sponsor type of token used to sponsor user operation
    enum Sponsor_Type {
        ETH,
        ERC20
    }

    // Struct for calls
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    // ------------------------------------------------------------------------------------
    //
    //                                       Helpers
    //
    // ------------------------------------------------------------------------------------

    // Deposit ETH into the Paymaster
    function _depositPaymaster() internal {
        vm.prank(address(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA));
        IPaymaster(address(paymaster)).deposit{ value: Constants.ETH_1 }();
    }

    // Get nonce for _sender from EntryPoint
    function _getNonce(address _sender) internal view returns (uint256) {
        return IEntryPoint(Constants.EP_V9_ADDRESS).getNonce(_sender, 0);
    }

    // Create UserOperation for AA transaction
    function _getUserOp(
        address _sender,
        uint256 _pk,
        bytes memory _callData,
        Sponsor_Type _sponsorType
    )
        internal
        view
        returns (PackedUserOperation[] memory)
    {
        PackedUserOperation[] memory u = new PackedUserOperation[](1);
        u[0].sender = _sender;
        u[0].nonce = _getNonce(_sender);
        u[0].accountGasLimits = bytes32(uint256(1_000_000 | (1_000_000 << 128)));
        u[0].gasFees = bytes32(uint256(1_000_000 | (1_000_000 << 128)));
        u[0].callData = _callData;

        if (_sponsorType == Sponsor_Type.ETH) {
            u[0].paymasterAndData = abi.encodePacked(
                address(paymaster), uint128(1_000_000), uint128(1_000_000), uint8(1), type(uint48).max, uint48(0)
            );

            bytes32 hash = SignatureCheckerLib.toEthSignedMessageHash(IPaymaster(address(paymaster)).getHash(0, u[0]));

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(__PAYMASTER_SIGNER_EOA, hash);

            u[0].paymasterAndData = abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(r, s, v));

            bytes32 userOpHash = IEntryPoint(Constants.EP_V9_ADDRESS).getUserOpHash(u[0]);
            (v, r, s) = vm.sign(_pk, userOpHash);
            u[0].signature = abi.encode(uint8(0), abi.encodePacked(r, s, v));
        } else if (_sponsorType == Sponsor_Type.ERC20) {
            u[0].paymasterAndData = abi.encodePacked(
                address(paymaster),
                uint128(1_000_000),
                uint128(1_000_000),
                uint8(1) | uint8(1 << 1),
                uint8(0),
                type(uint48).max,
                uint48(0),
                address(sponsorERC20),
                uint128(100_000),
                uint256(1e18),
                uint128(100_000),
                __PAYMASTER_SUPER_ADMIN_EOA
            );

            bytes32 hash = SignatureCheckerLib.toEthSignedMessageHash(IPaymaster(address(paymaster)).getHash(1, u[0]));

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(__PAYMASTER_SIGNER_EOA, hash);

            u[0].paymasterAndData = abi.encodePacked(u[0].paymasterAndData, abi.encodePacked(r, s, v));

            bytes32 userOpHash = IEntryPoint(Constants.EP_V9_ADDRESS).getUserOpHash(u[0]);
            (v, r, s) = vm.sign(_pk, userOpHash);
            u[0].signature = abi.encode(uint8(0), abi.encodePacked(r, s, v));
        }

        return u;
    }

    // Relay UserOperation to EntryPoint
    function _relayUserOp(PackedUserOperation[] memory _userOps) internal {
        vm.prank(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        IEntryPoint(Constants.EP_V9_ADDRESS).handleOps(_userOps, payable(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA));
    }
}
