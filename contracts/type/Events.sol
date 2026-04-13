// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";

/// @title Events
/// @dev Events emitted by the paymaster contracts.
library Events {
    /// @dev Emitted when a signer address is added (legacy, unused).
    event SignerAdded(address signer);
    /// @dev Emitted when a signer address is removed (legacy, unused).
    event SignerRemoved(address signer);
    /// @dev Emitted when a key is revoked from the paymaster.
    event Revoked(bytes32 indexed keyHash);
    /// @dev Emitted when a new key (superAdmin, admin, or signer) is authorized.
    event Authorized(bytes32 indexed keyHash, Key key);
    /// @dev Emitted in postOp (ERC-20 mode) or validatePaymasterUserOp (verifying mode)
    ///      after a user operation is successfully sponsored.
    /// @param userOpHash The hash of the sponsored user operation.
    /// @param user The account that requested sponsorship.
    /// @param paymasterMode The paymaster mode used (0 = verifying, 1 = ERC-20).
    /// @param token The ERC-20 token used for payment (address(0) in verifying mode).
    /// @param tokenAmountPaid The amount of tokens charged (0 in verifying mode).
    /// @param exchangeRate The token/ETH exchange rate applied (0 in verifying mode).
    event UserOperationSponsored(
        bytes32 indexed userOpHash,
        address indexed user,
        uint8 paymasterMode,
        address token,
        uint256 tokenAmountPaid,
        uint256 exchangeRate
    );
}
