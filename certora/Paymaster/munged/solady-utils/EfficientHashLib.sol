// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Munged (assembly-free) version of Solady's EfficientHashLib for Certora verification.
/// @dev Only includes functions actually used by the Paymaster contract chain.
///      Replaces inline assembly with equivalent pure Solidity to enable Certora's static analysis.
///      Original: https://github.com/vectorized/solady/blob/main/src/utils/EfficientHashLib.sol
library EfficientHashLib {
    /// @dev Returns `keccak256(abi.encode(v0))`.
    function hash(bytes32 v0) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(v0));
    }

    /// @dev Returns `keccak256(abi.encode(v0))`.
    function hash(uint256 v0) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(v0));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1))`.
    function hash(bytes32 v0, bytes32 v1) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(v0, v1));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1))`.
    /// This is the primary function used by KeyLib.hash() for access control.
    function hash(uint256 v0, uint256 v1) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(v0, v1));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1, v2))`.
    function hash(bytes32 v0, bytes32 v1, bytes32 v2) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(v0, v1, v2));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1, v2))`.
    function hash(uint256 v0, uint256 v1, uint256 v2) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(v0, v1, v2));
    }

    /// @dev Munged sha256 stub — returns keccak256 as a deterministic stand-in.
    ///      The real sha2 uses staticcall to SHA-256 precompile (address 2).
    ///      In Certora verification, P256 signature paths are summarized as NONDET,
    ///      so the actual SHA-256 output is irrelevant.
    function sha2(bytes32 b) internal pure returns (bytes32 result) {
        result = keccak256(abi.encode(b));
    }

    /// @dev Munged sha256 stub for bytes memory.
    function sha2(bytes memory b) internal pure returns (bytes32 result) {
        result = keccak256(b);
    }

    /// @dev Munged sha256 stub with start/end range.
    function sha2(bytes memory b, uint256 start, uint256 end)
        internal
        pure
        returns (bytes32 result)
    {
        bytes memory slice = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            slice[i - start] = b[i];
        }
        result = keccak256(slice);
    }

    /// @dev Munged sha256 stub with start only.
    function sha2(bytes memory b, uint256 start) internal pure returns (bytes32 result) {
        bytes memory slice = new bytes(b.length - start);
        for (uint256 i = start; i < b.length; i++) {
            slice[i - start] = b[i];
        }
        result = keccak256(slice);
    }
}
