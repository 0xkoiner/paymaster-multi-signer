// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Munged (assembly-free) EnumerableSetLib for Certora verification.
/// @dev Replaces Solady's assembly-optimized implementation with standard Solidity
///      to enable Certora Prover's static analysis. Only Bytes32Set is fully
///      implemented (the only type used by the Paymaster contracts).
library EnumerableSetLib {
    // ──────────────────────────────────────────────────────────────────────
    //  Struct Definitions (all types needed for `using ... for *`)
    // ──────────────────────────────────────────────────────────────────────

    struct AddressSet {
        address[] _values;
        mapping(address => uint256) _indexes;
    }

    struct Bytes32Set {
        bytes32[] _values;
        mapping(bytes32 => uint256) _indexes; // value -> position (1-indexed, 0 = absent)
    }

    struct Uint256Set {
        uint256[] _values;
        mapping(uint256 => uint256) _indexes;
    }

    struct Int256Set {
        int256[] _values;
        mapping(int256 => uint256) _indexes;
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Bytes32Set — full implementation (used by Paymaster keyHashes)
    // ──────────────────────────────────────────────────────────────────────

    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length; // 1-indexed
            return true;
        }
        return false;
    }

    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        uint256 position = set._indexes[value];
        if (position != 0) {
            // Swap with last element and pop
            uint256 lastIndex = set._values.length - 1;
            uint256 valueIndex = position - 1;

            if (valueIndex != lastIndex) {
                bytes32 lastValue = set._values[lastIndex];
                set._values[valueIndex] = lastValue;
                set._indexes[lastValue] = position;
            }

            set._values.pop();
            delete set._indexes[value];
            return true;
        }
        return false;
    }

    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(Bytes32Set storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return set._values[index];
    }

    // ──────────────────────────────────────────────────────────────────────
    //  AddressSet — stubs (not used by Paymaster, needed for compilation)
    // ──────────────────────────────────────────────────────────────────────

    function add(AddressSet storage set, address value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        }
        return false;
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        uint256 position = set._indexes[value];
        if (position != 0) {
            uint256 lastIndex = set._values.length - 1;
            uint256 valueIndex = position - 1;
            if (valueIndex != lastIndex) {
                address lastValue = set._values[lastIndex];
                set._values[valueIndex] = lastValue;
                set._indexes[lastValue] = position;
            }
            set._values.pop();
            delete set._indexes[value];
            return true;
        }
        return false;
    }

    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return set._values[index];
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Uint256Set — stubs
    // ──────────────────────────────────────────────────────────────────────

    function add(Uint256Set storage set, uint256 value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        }
        return false;
    }

    function remove(Uint256Set storage set, uint256 value) internal returns (bool) {
        uint256 position = set._indexes[value];
        if (position != 0) {
            uint256 lastIndex = set._values.length - 1;
            uint256 valueIndex = position - 1;
            if (valueIndex != lastIndex) {
                uint256 lastValue = set._values[lastIndex];
                set._values[valueIndex] = lastValue;
                set._indexes[lastValue] = position;
            }
            set._values.pop();
            delete set._indexes[value];
            return true;
        }
        return false;
    }

    function contains(Uint256Set storage set, uint256 value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(Uint256Set storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(Uint256Set storage set, uint256 index) internal view returns (uint256) {
        return set._values[index];
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Int256Set — stubs
    // ──────────────────────────────────────────────────────────────────────

    function add(Int256Set storage set, int256 value) internal returns (bool) {
        if (set._indexes[value] == 0) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        }
        return false;
    }

    function remove(Int256Set storage set, int256 value) internal returns (bool) {
        uint256 position = set._indexes[value];
        if (position != 0) {
            uint256 lastIndex = set._values.length - 1;
            uint256 valueIndex = position - 1;
            if (valueIndex != lastIndex) {
                int256 lastValue = set._values[lastIndex];
                set._values[valueIndex] = lastValue;
                set._indexes[lastValue] = position;
            }
            set._values.pop();
            delete set._indexes[value];
            return true;
        }
        return false;
    }

    function contains(Int256Set storage set, int256 value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(Int256Set storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(Int256Set storage set, uint256 index) internal view returns (int256) {
        return set._values[index];
    }
}
