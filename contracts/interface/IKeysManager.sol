// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key } from "../type/Types.sol";

interface IKeysManager {
    // ------------------------------------------------------------------------------------
    //
    //                                  Admin Management
    //
    // ------------------------------------------------------------------------------------

    /// @notice Authorize a new admin key. Caller must be superAdmin or EntryPoint.
    /// @param _key The admin key to authorize. Must have `isAdmin == true` and `isSuperAdmin == false`.
    /// @return keyHash The keccak256 hash identifier of the newly authorized key.
    function authorizeAdmin(Key memory _key) external returns (bytes32 keyHash);

    /// @notice Revoke any key by its hash. Caller must be superAdmin or EntryPoint.
    /// @param _keyHash The hash of the key to revoke.
    function revoke(bytes32 _keyHash) external;

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

    // ------------------------------------------------------------------------------------
    //
    //                                      Getters
    //
    // ------------------------------------------------------------------------------------

    /// @notice Return the total number of registered keys (including expired).
    function keyCount() external view returns (uint256);

    /// @notice Return the key stored at index `_i` in the enumerable set.
    /// @param _i Index in the key set.
    function keyAt(uint256 _i) external view returns (Key memory);

    /// @notice Return the key associated with a given hash.
    /// @param _keyHash The hash identifier of the key.
    /// @return key The decoded key struct.
    function getKey(bytes32 _keyHash) external view returns (Key memory key);

    /// @notice Return all non-expired keys and their hashes.
    /// @return keys   Array of non-expired key structs.
    /// @return hashes Array of corresponding key hashes.
    function getKeys() external view returns (Key[] memory keys, bytes32[] memory hashes);
}
