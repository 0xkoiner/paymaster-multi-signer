// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";

interface IMultiSigner {
    // ------------------------------------------------------------------------------------
    //
    //                                  Signer Management
    //
    // ------------------------------------------------------------------------------------

    /// @notice Add a new signer key. Caller must be superAdmin, admin, or EntryPoint.
    /// @param _signer The signer key to add. Must have `isSuperAdmin == false` and `isAdmin == false`.
    function addSigner(Key calldata _signer) external;

    /// @notice Remove a signer key by its hash. Caller must be superAdmin or EntryPoint.
    ///         Cannot remove superAdmin or admin keys (use `revoke` instead).
    /// @param _signer The hash of the signer key to remove.
    function removeSigner(bytes32 _signer) external;
}
