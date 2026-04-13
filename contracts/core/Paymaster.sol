// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Validations } from "./Validations.sol";
import { SignerType } from "../../contracts/type/Types.sol";
import { Eip7702Support } from "../library/Eip7702Support.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

abstract contract Paymaster is Validations {
    /// @notice Compute the hash that a paymaster signer must sign to authorize a user operation.
    ///         Includes the userOp fields (sender, nonce, gas, callData, paymasterAndData),
    ///         the signer type, the chain id, and an EIP-7702 init-code override when applicable.
    /// @param _mode       Paymaster mode — `0` for verifying, `1` for ERC-20.
    /// @param _userOp     The packed user operation whose fields are hashed.
    /// @param _signerType The signer key type used to produce the paymaster signature.
    /// @return The EIP-191 signed message hash the signer must sign.
    function getHash(
        uint8 _mode,
        PackedUserOperation calldata _userOp,
        SignerType _signerType
    )
        public
        view
        override
        returns (bytes32)
    {
        bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(_userOp);
        bytes32 originalHash = super.getHash(_mode, _userOp, _signerType);
        return keccak256(abi.encode(originalHash, overrideInitCodeHash));
    }
}
