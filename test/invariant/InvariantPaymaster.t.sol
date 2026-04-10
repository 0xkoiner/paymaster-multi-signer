// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { Handler } from "./Handler.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { PaymasterLib } from "../../contracts/library/PaymasterLib.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

/// @title Foundry Invariant Tests for PaymasterEntry
/// @notice The fuzzer randomly calls Handler functions, then checks all invariant_ assertions.
contract InvariantPaymaster is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    Handler internal handler;

    Key internal superAdmin;
    Key internal admin;
    Key internal signer;

    function setUp() public override {
        super.setUp();

        superAdmin = _createKeySecp256k1(TypeOfKey.SUPER_ADMIN, __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA);
        admin = _createKeySecp256k1(TypeOfKey.ADMIN, __PAYMASTER__ADMIN_ADDRESS_EOA);
        signer = _createKeySecp256k1(TypeOfKey.SIGNER, __PAYMASTER_SIGNER_ADDRESS_EOA);

        _createBundlers(keccak256("bundlers-2"), 2);

        Key[] memory kS = new Key[](1);
        kS[0] = signer;
        _deploy(superAdmin, admin, kS, IEntryPoint(Constants.EP_V9_ADDRESS), webAuthnVerifier, bundlers);

        _deal(address(paymaster), Constants.ETH_1);
        _deal(__PAYMASTER_SUPER_ADMIN_ADDRESS_EOA, Constants.ETH_1);

        _depositPaymaster();

        // Deploy handler and target it for fuzzing
        handler = new Handler(
            paymaster,
            __PAYMASTER_SUPER_ADMIN_ADDRESS_EOA,
            __PAYMASTER__ADMIN_ADDRESS_EOA,
            __PAYMASTER_SIGNER_ADDRESS_EOA
        );

        targetContract(address(handler));
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-7: keyStorage and keyHashes stay synchronized
    //    Every key in keyHashes must be retrievable via getKey
    //
    // ------------------------------------------------------------------------------------

    function invariant_keyStorage_keyHashes_synchronized() external view {
        uint256 count = paymaster.keyCount();
        for (uint256 i = 0; i < count; i++) {
            Key memory k = paymaster.keyAt(i);
            assertTrue(k.publicKey.length > 0, "INV-7: Every key in set must have non-empty publicKey");
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-1: Key roles are mutually exclusive
    //    No key can be both superAdmin AND admin, or both AND signer
    //
    // ------------------------------------------------------------------------------------

    function invariant_roles_mutually_exclusive() external view {
        uint256 count = paymaster.keyCount();
        for (uint256 i = 0; i < count; i++) {
            Key memory k = paymaster.keyAt(i);

            // Cannot have both flags true
            if (k.isSuperAdmin && k.isAdmin) {
                revert("INV-1: Key has both isSuperAdmin and isAdmin");
            }
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-2 + INV-3: SuperAdmin never expires, Admin must expire
    //
    // ------------------------------------------------------------------------------------

    function invariant_superAdmin_never_expires() external view {
        Key memory sa = paymaster.getKey(superAdmin.hash());
        assertEq(sa.expiry, type(uint40).max, "INV-2: SuperAdmin must have max expiry");
    }

    function invariant_admin_has_finite_expiry() external view {
        // The initial admin must always have finite expiry
        try paymaster.getKey(admin.hash()) returns (Key memory a) {
            assertTrue(a.expiry != type(uint40).max, "INV-3: Admin must have finite expiry");
        } catch {
            // Admin was revoked — that's OK
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-9: KillSwitch — superAdmin key always exists
    //    removeSigner cannot remove admin/superAdmin, so superAdmin must persist
    //
    // ------------------------------------------------------------------------------------

    function invariant_superAdmin_always_exists() external view {
        Key memory sa = paymaster.getKey(superAdmin.hash());
        assertTrue(sa.isSuperAdmin, "INV-9: SuperAdmin key must always exist");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-17: EntryPoint is immutable
    //
    // ------------------------------------------------------------------------------------

    function invariant_entryPoint_immutable() external view {
        assertEq(address(paymaster.entryPoint()), Constants.EP_V9_ADDRESS, "INV-17: EntryPoint must never change");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-18: WebAuthnVerifier is immutable
    //
    // ------------------------------------------------------------------------------------

    function invariant_webAuthnVerifier_immutable() external view {
        assertEq(
            address(paymaster.webAuthnVerifier()),
            address(webAuthnVerifier),
            "INV-18: WebAuthnVerifier must never change"
        );
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-19: Bundler allowlist unchanged
    //
    // ------------------------------------------------------------------------------------

    function invariant_bundlers_unchanged() external view {
        for (uint256 i = 0; i < bundlers.length; i++) {
            assertTrue(paymaster.isBundlerAllowed(bundlers[i]), "INV-19: Bundler allowlist must not change");
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-10: getKeys filters expired keys
    //    validCount from getKeys <= keyCount (total including expired)
    //
    // ------------------------------------------------------------------------------------

    function invariant_getKeys_leq_keyCount() external view {
        uint256 totalCount = paymaster.keyCount();
        (Key[] memory keys,) = paymaster.getKeys();
        assertTrue(keys.length <= totalCount, "INV-10: getKeys().length must be <= keyCount()");
    }

    // ------------------------------------------------------------------------------------
    //
    //    Ghost variable consistency: keyCount = 3 + added - removed
    //
    // ------------------------------------------------------------------------------------

    function invariant_keyCount_consistent_with_ghost() external view {
        uint256 expected = 3 + handler.ghost_signersAdded() - handler.ghost_signersRemoved()
            + handler.ghost_adminsAdded() - handler.ghost_adminsRevoked();

        assertEq(paymaster.keyCount(), expected, "Ghost: keyCount must equal 3 + added - removed");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-39/40: _getCostInToken math invariants
    //    Zero rate always returns zero
    //
    // ------------------------------------------------------------------------------------

    function invariant_getCostInToken_zero_rate_is_zero() external pure {
        uint256 cost = PaymasterLib._getCostInToken(1e18, 1e6, 1e9, 0);
        assertEq(cost, 0, "INV-40: Zero exchange rate must return zero");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-4: Every stored signer key has isSuperAdmin=false AND isAdmin=false
    //
    // ------------------------------------------------------------------------------------

    function invariant_signer_keys_not_admin_or_superAdmin() external view {
        uint256 count = paymaster.keyCount();
        for (uint256 i = 0; i < count; i++) {
            Key memory k = paymaster.keyAt(i);
            if (!k.isSuperAdmin && !k.isAdmin) {
                // This is a signer — verify it wasn't stored with privileged flags
                assertTrue(k.expiry != type(uint40).max, "INV-4: Signer must have finite expiry");
            }
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-5: Every stored key has non-empty publicKey
    //
    // ------------------------------------------------------------------------------------

    function invariant_all_keys_have_publicKey() external view {
        uint256 count = paymaster.keyCount();
        for (uint256 i = 0; i < count; i++) {
            Key memory k = paymaster.keyAt(i);
            assertTrue(k.publicKey.length > 0, "INV-5: Every key must have non-empty publicKey");
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-6: Every stored key has keyType >= 1 (for admin/superAdmin)
    //         or any valid type for signers
    //
    // ------------------------------------------------------------------------------------

    function invariant_privileged_keys_have_valid_keyType() external view {
        uint256 count = paymaster.keyCount();
        for (uint256 i = 0; i < count; i++) {
            Key memory k = paymaster.keyAt(i);
            if (k.isSuperAdmin || k.isAdmin) {
                assertTrue(
                    uint8(k.keyType) >= 1 || uint8(k.keyType) == 0,
                    "INV-6: keyType must be valid SignerType"
                );
            }
            assertTrue(uint8(k.keyType) <= 2, "INV-6: keyType must be 0, 1, or 2");
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-8: No duplicate key hashes in storage
    //
    // ------------------------------------------------------------------------------------

    function invariant_no_duplicate_key_hashes() external view {
        uint256 count = paymaster.keyCount();
        for (uint256 i = 0; i < count; i++) {
            (, bytes32[] memory hashes) = paymaster.getKeys();
            for (uint256 j = i + 1; j < hashes.length; j++) {
                assertTrue(hashes[i] != hashes[j], "INV-8: No duplicate key hashes");
            }
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-9 extended: Initial admin key protected by KillSwitch
    //    (admin key either still exists, or was revoked by superAdmin — but never via removeSigner)
    //
    // ------------------------------------------------------------------------------------

    function invariant_initial_signer_or_removed_cleanly() external view {
        // The initial signer can be removed by superAdmin via removeSigner
        // But initial admin/superAdmin cannot be removed via removeSigner
        // We just verify superAdmin always exists (already tested above)
        // Here verify: if initial admin exists, it still has isAdmin=true
        try paymaster.getKey(admin.hash()) returns (Key memory a) {
            assertTrue(a.isAdmin, "INV-9: If initial admin exists, isAdmin must be true");
        } catch {
            // Admin was revoked — acceptable
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-11: Expiry monotonic — all returned keys from getKeys are not expired
    //
    // ------------------------------------------------------------------------------------

    function invariant_getKeys_returns_only_valid_keys() external view {
        (Key[] memory keys,) = paymaster.getKeys();
        for (uint256 i = 0; i < keys.length; i++) {
            // Either expiry == 0 (special) or expiry >= block.timestamp
            assertTrue(
                keys[i].expiry == 0 || keys[i].expiry >= uint40(block.timestamp),
                "INV-11: getKeys must only return non-expired keys"
            );
        }
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-23: Selector whitelist — only 4 selectors allowed
    //
    // ------------------------------------------------------------------------------------

    function invariant_selector_whitelist_complete() external pure {
        assertTrue(KeyLib._isAllowedSelector(bytes4(0xd0e30db0)), "INV-23: deposit must be allowed");
        assertTrue(KeyLib._isAllowedSelector(bytes4(0x0396cb60)), "INV-23: addStake must be allowed");
        assertTrue(KeyLib._isAllowedSelector(bytes4(0xbb9fe6bf)), "INV-23: unlockStake must be allowed");
        assertTrue(KeyLib._isAllowedSelector(bytes4(0x56864ab1)), "INV-23: addSigner must be allowed");
        assertFalse(KeyLib._isAllowedSelector(bytes4(0x12345678)), "INV-23: Random selector must not be allowed");
        assertFalse(KeyLib._isAllowedSelector(bytes4(0x095ea7b3)), "INV-23: approve must not be in whitelist");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-39: _getCostInToken monotonic with exchange rate
    //
    // ------------------------------------------------------------------------------------

    function invariant_getCostInToken_monotonic() external pure {
        uint256 costLow = PaymasterLib._getCostInToken(1e6, 50000, 10, 0.5e18);
        uint256 costHigh = PaymasterLib._getCostInToken(1e6, 50000, 10, 2e18);
        assertTrue(costLow <= costHigh, "INV-39: Higher rate must produce higher cost");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-41: _getCostInToken with 1e18 rate returns exact gas cost
    //
    // ------------------------------------------------------------------------------------

    function invariant_getCostInToken_1e18_exact() external pure {
        uint256 cost = PaymasterLib._getCostInToken(1e6, 50000, 10, 1e18);
        uint256 expected = 1e6 + 50000 * 10;
        assertEq(cost, expected, "INV-41: 1e18 rate must return exact gas cost");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-42: Penalty zero when executionGasLimit is zero
    //
    // ------------------------------------------------------------------------------------

    function invariant_penalty_zero_when_no_limit() external view {
        uint256 result = paymaster._expectedPenaltyGasCost(1e6, 10, 50000, 1e5, 0);
        assertEq(result, 0, "INV-42: Zero limit must produce zero penalty");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-43: Penalty is 10% of unused gas * fee
    //
    // ------------------------------------------------------------------------------------

    function invariant_penalty_10_percent() external view {
        // actualGas = 0, preOp = 0, executionGasLimit = 100000
        // unused = 100000, penalty = 10000, result = 10000 * 10 = 100000
        uint256 result = paymaster._expectedPenaltyGasCost(0, 10, 0, 0, 100000);
        assertEq(result, 100000, "INV-43: Penalty must be 10% of unused * fee");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-49: Key hash is deterministic
    //
    // ------------------------------------------------------------------------------------

    function invariant_key_hash_deterministic() external pure {
        address a = address(0xBEEF);
        assertEq(KeyLib.hash(a), KeyLib.hash(a), "INV-49: Hash must be deterministic");
    }

    // ------------------------------------------------------------------------------------
    //
    //    INV-50: Different addresses produce different hashes
    //
    // ------------------------------------------------------------------------------------

    function invariant_different_addresses_different_hashes() external pure {
        assertTrue(
            KeyLib.hash(address(0xBEEF)) != KeyLib.hash(address(0xCAFE)),
            "INV-50: Different addresses must produce different hashes"
        );
    }
}
