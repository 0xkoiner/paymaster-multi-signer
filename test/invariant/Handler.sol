// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Test } from "../../lib/forge-std/src/Test.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { PaymasterEntry } from "../../contracts/core/PaymasterEntry.sol";

/// @title Handler — Fuzzer-callable wrapper around PaymasterEntry
/// @notice The invariant fuzzer calls functions on this contract in random order.
///         Each function wraps a paymaster state-change with proper vm.prank and bounded inputs.
///         Ghost variables track expected state for invariant assertions.
contract Handler is Test {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                   External State
    //
    // ------------------------------------------------------------------------------------

    PaymasterEntry public paymaster;
    address public superAdminEoa;
    address public adminEoa;
    address public signerEoa;

    // ------------------------------------------------------------------------------------
    //
    //                                   Ghost Variables
    //
    // ------------------------------------------------------------------------------------

    /// @dev Tracks number of signers added (not admins, not superAdmin)
    uint256 public ghost_signersAdded;

    /// @dev Tracks number of signers removed
    uint256 public ghost_signersRemoved;

    /// @dev Tracks number of admins added
    uint256 public ghost_adminsAdded;

    /// @dev Tracks number of admins revoked
    uint256 public ghost_adminsRevoked;

    /// @dev Tracks total deposits made
    uint256 public ghost_totalDeposited;

    /// @dev Counter for unique signer addresses
    uint256 private _signerNonce;

    /// @dev Counter for unique admin addresses
    uint256 private _adminNonce;

    /// @dev Track added signer hashes to avoid duplicates
    mapping(bytes32 => bool) public ghost_signerExists;

    /// @dev Track added admin hashes to avoid duplicates
    mapping(bytes32 => bool) public ghost_adminExists;

    // ------------------------------------------------------------------------------------
    //
    //                                   Constructor
    //
    // ------------------------------------------------------------------------------------

    constructor(PaymasterEntry _paymaster, address _superAdminEoa, address _adminEoa, address _signerEoa) {
        paymaster = _paymaster;
        superAdminEoa = _superAdminEoa;
        adminEoa = _adminEoa;
        signerEoa = _signerEoa;
    }

    // ------------------------------------------------------------------------------------
    //
    //                            Fuzzer-Callable Functions
    //
    // ------------------------------------------------------------------------------------

    /// @notice SuperAdmin adds a new signer with a unique address
    function addSigner(uint256 _seed) external {
        _signerNonce++;
        address newSignerAddr = address(uint160(uint256(keccak256(abi.encode(_seed, _signerNonce)))));

        Key memory k;
        k.expiry = uint40(block.timestamp + 365 days);
        k.keyType = SignerType.Secp256k1;
        k.isSuperAdmin = false;
        k.isAdmin = false;
        k.publicKey = abi.encode(newSignerAddr);

        bytes32 keyHash = k.hash();

        // Skip if would be a duplicate (hash collision with existing key)
        if (ghost_signerExists[keyHash]) return;

        vm.prank(superAdminEoa);
        try paymaster.addSigner(k) {
            ghost_signersAdded++;
            ghost_signerExists[keyHash] = true;
        } catch { }
    }

    /// @notice Admin adds a new signer with a unique address
    function adminAddSigner(uint256 _seed) external {
        _signerNonce++;
        address newSignerAddr = address(uint160(uint256(keccak256(abi.encode(_seed, _signerNonce, "admin")))));

        Key memory k;
        k.expiry = uint40(block.timestamp + 365 days);
        k.keyType = SignerType.Secp256k1;
        k.isSuperAdmin = false;
        k.isAdmin = false;
        k.publicKey = abi.encode(newSignerAddr);

        bytes32 keyHash = k.hash();
        if (ghost_signerExists[keyHash]) return;

        vm.prank(adminEoa);
        try paymaster.addSigner(k) {
            ghost_signersAdded++;
            ghost_signerExists[keyHash] = true;
        } catch { }
    }

    /// @notice SuperAdmin removes the most recently added signer
    function removeSigner(uint256 _seed) external {
        uint256 count = paymaster.keyCount();
        if (count <= 3) return; // Don't remove initial 3 keys

        // Pick a key index beyond the initial 3
        uint256 idx = 3 + (_seed % (count - 3));
        Key memory k = paymaster.keyAt(idx);
        bytes32 keyHash = k.hash();

        // Only remove signers (not admin/superAdmin)
        if (k.isSuperAdmin || k.isAdmin) return;

        vm.prank(superAdminEoa);
        try paymaster.removeSigner(keyHash) {
            ghost_signersRemoved++;
            ghost_signerExists[keyHash] = false;
        } catch { }
    }

    /// @notice SuperAdmin authorizes a new admin
    function authorizeAdmin(uint256 _seed) external {
        _adminNonce++;
        address newAdminAddr = address(uint160(uint256(keccak256(abi.encode(_seed, _adminNonce, "admin-auth")))));

        Key memory k;
        k.expiry = uint40(block.timestamp + 365 days);
        k.keyType = SignerType.Secp256k1;
        k.isSuperAdmin = false;
        k.isAdmin = true;
        k.publicKey = abi.encode(newAdminAddr);

        bytes32 keyHash = k.hash();
        if (ghost_adminExists[keyHash]) return;

        vm.prank(superAdminEoa);
        try paymaster.authorizeAdmin(k) {
            ghost_adminsAdded++;
            ghost_adminExists[keyHash] = true;
        } catch { }
    }

    /// @notice SuperAdmin revokes an admin (picks one beyond initial 3)
    function revokeAdmin(uint256 _seed) external {
        uint256 count = paymaster.keyCount();
        if (count <= 3) return;

        uint256 idx = 3 + (_seed % (count - 3));
        Key memory k = paymaster.keyAt(idx);
        bytes32 keyHash = k.hash();

        // Only revoke admins via this function
        if (!k.isAdmin) return;

        vm.prank(superAdminEoa);
        try paymaster.revoke(keyHash) {
            ghost_adminsRevoked++;
            ghost_adminExists[keyHash] = false;
        } catch { }
    }

    /// @notice SuperAdmin deposits ETH
    function deposit(uint256 _amount) external {
        _amount = bound(_amount, 0.001 ether, 0.1 ether);

        vm.deal(superAdminEoa, _amount);
        vm.prank(superAdminEoa);
        try paymaster.deposit{ value: _amount }() {
            ghost_totalDeposited += _amount;
        } catch { }
    }

    /// @notice Warp time forward to test expiry
    function warpForward(uint256 _seconds) external {
        _seconds = bound(_seconds, 1, 365 days);
        vm.warp(block.timestamp + _seconds);
    }
}
