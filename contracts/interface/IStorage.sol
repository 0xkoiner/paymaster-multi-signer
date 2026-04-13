// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { IWebAuthnVerifier } from "./IWebAuthnVerifier.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

interface IStorage {
    // ------------------------------------------------------------------------------------
    //
    //                              Storage Getters
    //
    // ------------------------------------------------------------------------------------

    /// @notice The immutable ERC-4337 EntryPoint this paymaster is bound to.
    function entryPoint() external view returns (IEntryPoint);

    /// @notice The immutable WebAuthn P256 signature verifier contract.
    function webAuthnVerifier() external view returns (IWebAuthnVerifier);

    /// @notice Whether an address is registered as a valid signer.
    /// @param account The address to check.
    function signers(address account) external view returns (bool isValidSigner);

    /// @notice Whether a bundler address is allowed to submit user operations.
    /// @param bundler The bundler address to check.
    function isBundlerAllowed(address bundler) external view returns (bool allowed);
}
