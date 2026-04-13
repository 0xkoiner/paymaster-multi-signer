// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Errors } from "../type/Errors.sol";
import { UserOperationLib } from "@account-abstraction/contracts/core/UserOperationLib.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title Eip7702Support
/// @dev Helpers for detecting and resolving EIP-7702 delegation designators in userOp initCode.
library Eip7702Support {
    using UserOperationLib for PackedUserOperation;

    bytes3 internal constant EIP7702_PREFIX = 0xef0100;
    bytes2 internal constant INITCODE_EIP7702_MARKER = 0x7702;

    /// @dev If the userOp uses an EIP-7702 initCode marker, return a hash override that replaces the
    ///      initCode hash with the sender's actual delegation target. Returns `bytes32(0)` otherwise.
    function _getEip7702InitCodeHashOverride(PackedUserOperation calldata _userOp) internal view returns (bytes32) {
        bytes calldata initCode = _userOp.initCode;
        if (!_isEip7702InitCode(initCode)) {
            return 0;
        }
        address delegate = _getEip7702Delegate(_userOp.sender);
        if (initCode.length <= 20) return keccak256(abi.encodePacked(delegate));
        else return keccak256(abi.encodePacked(delegate, initCode[20:]));
    }

    /// @dev Return true if `initCode` starts with the `0x7702` EIP-7702 marker prefix.
    function _isEip7702InitCode(bytes calldata initCode) internal pure returns (bool) {
        if (initCode.length < 2) {
            return false;
        }
        bytes20 initCodeStart;

        assembly {
            initCodeStart := calldataload(initCode.offset)
        }

        return initCodeStart == bytes20(INITCODE_EIP7702_MARKER);
    }

    /// @dev Read the first 23 bytes of `_sender`'s code and extract the EIP-7702 delegation target.
    ///      Reverts if the code does not start with the `0xef0100` prefix or the sender has no code.
    function _getEip7702Delegate(address _sender) internal view returns (address) {
        bytes32 senderCode;

        assembly {
            extcodecopy(_sender, 0, 0, 23)
            senderCode := mload(0)
        }

        if (bytes3(senderCode) != EIP7702_PREFIX) {
            require(_sender.code.length > 0, Errors.SenderHasNoCode());
            revert Errors.NotEIP7702Delegate();
        }
        return address(bytes20(senderCode << 24));
    }
}
