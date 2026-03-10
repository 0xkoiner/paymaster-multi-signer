// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { SignerType } from "../../contracts/type/Types.sol";
import { PackedUserOperation } from "lib/account-abstraction-v9/contracts/interfaces/PackedUserOperation.sol";

interface IPaymaster {
    function deposit() external payable;
    function getHash(
        uint8 _mode,
        PackedUserOperation calldata _userOp,
        SignerType _signerType
    )
        external
        view
        returns (bytes32);
    function validatePaymasterUserOp(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        external
        returns (bytes memory context, uint256 validationData);
}
