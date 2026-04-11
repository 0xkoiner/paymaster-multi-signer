// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Munged (assembly-free for storage ops) LibBytes for Certora verification.
/// @dev BytesStorage operations replaced with standard Solidity `bytes`.
///      Calldata/memory utility functions use minimal assembly where unavoidable.
///      Original: https://github.com/vectorized/solady/blob/main/src/utils/LibBytes.sol
library LibBytes {
    // ──────────────────────────────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────────────────────────────

    /// @dev Munged BytesStorage — uses standard Solidity `bytes` instead of
    ///      Solady's packed single-slot assembly layout.
    struct BytesStorage {
        bytes _data;
    }

    uint256 internal constant NOT_FOUND = type(uint256).max;

    // ──────────────────────────────────────────────────────────────────────
    //  BytesStorage Operations (fully munged — no assembly)
    // ──────────────────────────────────────────────────────────────────────

    /// @dev Sets the value of the bytes storage `$` to `s`.
    function set(BytesStorage storage $, bytes memory s) internal {
        $._data = s;
    }

    /// @dev Clears the bytes storage `$`.
    function clear(BytesStorage storage $) internal {
        delete $._data;
    }

    /// @dev Returns the length of the bytes storage `$`.
    function length(BytesStorage storage $) internal view returns (uint256) {
        return $._data.length;
    }

    /// @dev Returns the bytes stored in `$`.
    function get(BytesStorage storage $) internal view returns (bytes memory) {
        return $._data;
    }

    /// @dev Returns the byte at position `i` in storage `$`.
    function uint8At(BytesStorage storage $, uint256 i) internal view returns (uint8) {
        return uint8($._data[i]);
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Memory Operations
    // ──────────────────────────────────────────────────────────────────────

    /// @dev Loads a 32-byte word from `b` at byte offset `o`.
    function load(bytes memory b, uint256 o) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(add(b, 0x20), o))
        }
    }

    /// @dev Truncates `b` in-place to length `n`.
    function truncate(bytes memory b, uint256 n) internal pure returns (bytes memory) {
        assembly {
            mstore(b, n)
        }
        return b;
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Calldata Operations (kept with minimal assembly — read-only,
    //  these do NOT cause Certora static analysis failures)
    // ──────────────────────────────────────────────────────────────────────

    /// @dev Loads a 32-byte word from calldata `b` at byte offset `o`.
    function loadCalldata(bytes calldata b, uint256 o) internal pure returns (bytes32 result) {
        assembly {
            result := calldataload(add(b.offset, o))
        }
    }

    /// @dev Returns a slice of calldata `b` starting at byte offset `o`.
    function sliceCalldata(bytes calldata b, uint256 o)
        internal
        pure
        returns (bytes calldata result)
    {
        assembly {
            result.offset := add(b.offset, o)
            result.length := sub(b.length, o)
        }
    }

    /// @dev Parses a dynamic struct from calldata. The struct offset is read
    ///      from `b` at position `o`, then the struct data starts there.
    function dynamicStructInCalldata(bytes calldata b, uint256 o)
        internal
        pure
        returns (bytes calldata result)
    {
        assembly {
            let s := add(b.offset, calldataload(add(b.offset, o)))
            result.offset := s
            result.length := sub(add(b.offset, b.length), s)
        }
    }

    /// @dev Parses a `bytes` field from a calldata struct at offset `o`.
    function bytesInCalldata(bytes calldata b, uint256 o)
        internal
        pure
        returns (bytes calldata result)
    {
        assembly {
            let s := add(b.offset, calldataload(add(b.offset, o)))
            result.offset := add(s, 0x20)
            result.length := calldataload(s)
        }
    }
}
