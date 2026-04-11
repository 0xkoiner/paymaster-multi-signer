// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Key, SignerType, Call } from "../../contracts/type/Types.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { PaymasterEntry } from "../../contracts/core/PaymasterEntry.sol";
import { PaymasterLib } from "../../contracts/library/PaymasterLib.sol";
import { LibBytes } from "@solady/src/utils/LibBytes.sol";
import { EnumerableSetLib } from "@solady/src/utils/EnumerableSetLib.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IWebAuthnVerifier } from "../../contracts/interface/IWebAuthnVerifier.sol";

/// @title PaymasterHarness
/// @notice Exposes internal state and helper functions for Certora formal verification.
/// @dev Inherits the full PaymasterEntry chain; adds view/pure getters only.
contract PaymasterHarness is PaymasterEntry {
    using KeyLib for *;
    using PaymasterLib for *;
    using LibBytes for LibBytes.BytesStorage;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    constructor(
        Key memory _superAdmin,
        Key memory _admin,
        Key[] memory _signers,
        IEntryPoint _entryPoint,
        IWebAuthnVerifier _webAuthnVerifier,
        address[] memory _allowedBundlers
    ) PaymasterEntry(_superAdmin, _admin, _signers, _entryPoint, _webAuthnVerifier, _allowedBundlers) {}

    // ═══════════════════════════════════════════════════════════
    //  State Exposure — read-only access to internal state
    // ═══════════════════════════════════════════════════════════

    /// @notice Returns the byte-length of the encoded key data for a given hash.
    function getKeyStorageLength(bytes32 _hash) external view returns (uint256) {
        return keyStorage[_hash].length();
    }

    /// @notice Returns true if the key hash is a member of the keyHashes set.
    function isKeyInSet(bytes32 _hash) external view returns (bool) {
        return keyHashes.contains(_hash);
    }

    /// @notice Returns the total number of keys in the keyHashes set.
    function getKeyCountHarness() external view returns (uint256) {
        return keyHashes.length();
    }

    /// @notice Returns true if the key stored at _hash has the SuperAdmin role.
    function isKeySuperAdminHarness(bytes32 _hash) external view returns (bool) {
        if (keyStorage[_hash].length() == 0) return false;
        return keyStorage[_hash]._isSuperAdmin();
    }

    /// @notice Returns true if the key stored at _hash has the Admin role.
    function isKeyAdminHarness(bytes32 _hash) external view returns (bool) {
        if (keyStorage[_hash].length() == 0) return false;
        return keyStorage[_hash]._isAdmin();
    }

    /// @notice Returns the immutable EntryPoint address.
    function getEntryPointAddress() external view returns (address) {
        return address(entryPoint);
    }

    /// @notice Returns the address of this contract (used for self-call checks).
    function getSelfAddress() external view returns (address) {
        return address(this);
    }

    /// @notice Computes the KeyLib hash of an address (Secp256k1 key type).
    function hashAddressHarness(address _addr) external pure returns (bytes32) {
        return _addr.hash();
    }

    /// @notice Returns true if the address has NO registered key in keyStorage.
    ///         Wraps the hash computation + storage lookup in a single call to
    ///         avoid exposing the assembly-heavy hash to CVL.
    function senderHasNoKey(address _addr) external view returns (bool) {
        bytes32 h = _addr.hash();
        return keyStorage[h].length() == 0;
    }

    // ═══════════════════════════════════════════════════════════
    //  Key Role Helpers — pure/view functions on Key struct fields
    // ═══════════════════════════════════════════════════════════

    /// @notice Pure check: does a Key with these fields satisfy _isSuperAdmin()?
    function keyIsSuperAdminPure(
        uint40 _expiry,
        uint8 _keyType,
        bool _isSuperAdmin,
        bool _isAdmin,
        uint256 _pkLen
    ) external pure returns (bool) {
        Key memory k;
        k.expiry = _expiry;
        k.keyType = SignerType(_keyType);
        k.isSuperAdmin = _isSuperAdmin;
        k.isAdmin = _isAdmin;
        k.publicKey = new bytes(_pkLen);
        return k._isSuperAdmin();
    }

    /// @notice Pure check: does a Key with these fields satisfy _isAdmin()?
    function keyIsAdminPure(
        uint40 _expiry,
        uint8 _keyType,
        bool _isSuperAdmin,
        bool _isAdmin,
        uint256 _pkLen
    ) external pure returns (bool) {
        Key memory k;
        k.expiry = _expiry;
        k.keyType = SignerType(_keyType);
        k.isSuperAdmin = _isSuperAdmin;
        k.isAdmin = _isAdmin;
        k.publicKey = new bytes(_pkLen);
        return k._isAdmin();
    }

    /// @notice Pure check: does a Key with these fields satisfy _isSigner()?
    function keyIsSignerPure(
        uint40 _expiry,
        uint8 _keyType,
        bool _isSuperAdmin,
        bool _isAdmin,
        uint256 _pkLen
    ) external pure returns (bool) {
        Key memory k;
        k.expiry = _expiry;
        k.keyType = SignerType(_keyType);
        k.isSuperAdmin = _isSuperAdmin;
        k.isAdmin = _isAdmin;
        k.publicKey = new bytes(_pkLen);
        return k._isSigner();
    }

    /// @notice View check: does _keyValidation pass for the given expiry?
    ///         Uses block.timestamp internally, so NOT envfree.
    function keyValidationView(uint40 _expiry) external view returns (bool) {
        Key memory k;
        k.expiry = _expiry;
        return k._keyValidation();
    }

    // ═══════════════════════════════════════════════════════════
    //  Selector Validation Helpers
    // ═══════════════════════════════════════════════════════════

    /// @notice Returns true if the selector is in the Admin-allowed list.
    function isAllowedSelectorHarness(bytes4 _sel) external pure returns (bool) {
        return _sel._isAllowedSelector();
    }

    /// @notice Exposes _validateCallData for verification of batch call validation (F-3).
    function validateCallDataHarness(bytes calldata _callData) external view returns (bool) {
        return _validateCallData(_callData);
    }

    // ═══════════════════════════════════════════════════════════
    //  Arithmetic Helpers
    // ═══════════════════════════════════════════════════════════

    /// @notice Wrapper for PaymasterLib._getCostInToken (PE-7).
    function getCostInTokenHarness(
        uint256 _actualGasCost,
        uint256 _postOpGas,
        uint256 _feePerGas,
        uint256 _exchangeRate
    ) external pure returns (uint256) {
        return _actualGasCost._getCostInToken(_postOpGas, _feePerGas, _exchangeRate);
    }
}
