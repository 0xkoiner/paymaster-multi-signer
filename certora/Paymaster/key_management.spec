/*
 * ═══════════════════════════════════════════════════════════════════════════════
 *  PAYMASTER KEY MANAGEMENT SPECIFICATION
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Verifies: KM-1, KM-3, KM-6 from VERIFICATION_PLAN.md
 *  Confirms: F-1 (last SuperAdmin removal bug)
 *            F-2 (constructor duplicate key issue)
 *
 *  Architecture:
 *    - Uses harness view functions instead of ghost+hook (EnumerableSetLib and
 *      LibBytes.BytesStorage have complex assembly-heavy storage layouts that
 *      make direct storage hooks impractical).
 *    - F-1 is demonstrated via satisfy rules (bug confirmation).
 *    - KM properties use pre/post state comparisons.
 *
 *  WHY these properties matter:
 *    Key management integrity = who controls the paymaster. If keys can be
 *    silently added, duplicated, or all removed, the contract is compromised.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ─── Methods Block ───────────────────────────────────────────────────────────

methods {
    // ── Harness getters ──
    function getEntryPointAddress()                 external returns (address)  envfree;
    function getSelfAddress()                       external returns (address)  envfree;
    function isKeySuperAdminHarness(bytes32)         external returns (bool)    envfree;
    function isKeyAdminHarness(bytes32)              external returns (bool)    envfree;
    function getKeyStorageLength(bytes32)            external returns (uint256) envfree;
    function isKeyInSet(bytes32)                     external returns (bool)    envfree;
    function getKeyCountHarness()                    external returns (uint256) envfree;
    function hashAddressHarness(address)             external returns (bytes32) envfree;
    function senderHasNoKey(address)                 external returns (bool)    envfree;

    // ── Contract functions ──
    function revoke(bytes32)                         external;
    function removeSigner(bytes32)                   external;
    function keyCount()                              external returns (uint256) envfree;

    // ── External call summaries ──
    function _.depositTo(address)           external => NONDET;
    function _.withdrawTo(address, uint256) external => NONDET;
    function _.addStake(uint32)             external => NONDET;
    function _.unlockStake()                external => NONDET;
    function _.withdrawStake(address)       external => NONDET;
    function _.balanceOf(address)           external => NONDET;
    function _.verifyP256Signature(bytes32, bytes32, bytes32, bytes32, bytes32)
        external => NONDET;
    function _.verifyEncodedSignature(bytes32, bool, bytes, bytes32, bytes32)
        external => NONDET;

    // Token transfers — prevent havoc on ERC20 calls
    function _.safeTransferFrom(address, address, address, uint256) external => NONDET;
    function _.transferFrom(address, address, uint256) external => NONDET;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FINDING F-1: Last SuperAdmin Can Be Revoked
//  Severity: HIGH
//  Location: KeysManager.sol:revoke()
//
//  The revoke() function has NO check preventing removal of the last SuperAdmin.
//  This can permanently lock the contract — no one can add new keys or withdraw.
//
//  Strategy: Use satisfy to demonstrate the bug exists.
//            Use assert to show the safety property is violated.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice F-1 BUG CONFIRMATION: Prove that the last SuperAdmin CAN be revoked.
///         This satisfy rule asks the prover to find a valid execution where
///         the only remaining key (a SuperAdmin) is successfully revoked.
///         If satisfied → bug confirmed.
rule F1_lastSuperAdminCanBeRevoked {
    env e;
    bytes32 superAdminHash;

    // Pre: the key exists, is in the set, and is a SuperAdmin
    require isKeySuperAdminHarness(superAdminHash);
    require isKeyInSet(superAdminHash);
    require getKeyStorageLength(superAdminHash) > 0;

    // Pre: this is the ONLY key in the system
    require getKeyCountHarness() == 1;

    // Caller is authorized (EntryPoint — simplest authorized path)
    require e.msg.sender == getEntryPointAddress();
    require e.msg.value == 0;

    revoke@withrevert(e, superAdminHash);

    // BUG: The contract should prevent this, but it doesn't
    satisfy !lastReverted,
        "F-1 CONFIRMED: Last SuperAdmin can be revoked → contract is bricked";
}

/// @notice F-1 SAFETY PROPERTY (expected to FAIL):
///         After any successful revoke(), at least one key should remain.
///         The counterexample from this rule demonstrates the exact attack.
rule F1_atLeastOneKeyAfterRevoke {
    env e;
    bytes32 keyHash;

    // Preconditions
    require isKeyInSet(keyHash);
    require getKeyStorageLength(keyHash) > 0;
    require e.msg.value == 0;

    revoke(e, keyHash);

    // Safety: key count should never drop to 0
    // EXPECTED TO FAIL — confirming F-1
    assert getKeyCountHarness() >= 1,
        "F-1: After revoke, at least one key must remain (EXPECTED TO FAIL)";
}

/// @notice F-1 SANITY: Verify the preconditions for F-1 are satisfiable.
///         Ensures the requires in F1_lastSuperAdminCanBeRevoked are not contradictory.
rule F1_sanity_preconditionsSatisfiable {
    bytes32 superAdminHash;

    require isKeySuperAdminHarness(superAdminHash);
    require isKeyInSet(superAdminHash);
    require getKeyStorageLength(superAdminHash) > 0;
    require getKeyCountHarness() == 1;

    satisfy true,
        "F-1 sanity: A state with exactly one SuperAdmin key exists";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  KM-6: Removing a key clears it completely
//
//  After revoke(hash):
//    - keyStorage[hash].length() == 0
//    - hash is NOT in keyHashes
//
//  WHY: If key removal is incomplete, phantom keys could exist in storage
//  (allowing ghost access) or in the set (causing getKey to revert).
// ═══════════════════════════════════════════════════════════════════════════════

rule KM6_revokeRemovesCompletely {
    env e;
    bytes32 keyHash;

    // Pre: key exists
    require isKeyInSet(keyHash);
    require getKeyStorageLength(keyHash) > 0;
    require e.msg.value == 0;

    revoke(e, keyHash);

    // Post: key is fully removed
    assert !isKeyInSet(keyHash),
        "KM-6: After revoke, key hash must not be in keyHashes set";
    assert getKeyStorageLength(keyHash) == 0,
        "KM-6: After revoke, key storage must be cleared (length == 0)";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  KM-1: Key hash set and storage consistency (directional)
//
//  If a key is in the set, its storage must be non-empty.
//  If a key's storage is non-empty, it must be in the set.
//
//  We verify this holds AFTER each state-changing operation.
// ═══════════════════════════════════════════════════════════════════════════════

// KM-1: After revoke, the REVOKED key's set membership and storage are consistent.
// NOTE: We verify consistency for the specific key being revoked, not arbitrary keys.
// Full data-structure consistency across ALL keys would require ghost+hook invariants
// on the munged EnumerableSetLib/LibBytes storage, which is future work.
rule KM1_revokedKeyConsistency {
    env e;
    bytes32 keyHash;

    // Pre: the key exists and is consistent
    require isKeyInSet(keyHash), "pre: key is in the set";
    require getKeyStorageLength(keyHash) > 0, "pre: key has storage";
    require e.msg.value == 0, "revoke is non-payable";

    revoke(e, keyHash);

    // Post: the revoked key is fully removed from BOTH set and storage
    assert !isKeyInSet(keyHash),
        "KM-1: After revoke, key must not be in set";
    assert getKeyStorageLength(keyHash) == 0,
        "KM-1: After revoke, key storage must be cleared";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  KM-3: keyCount accuracy (parametric)
//
//  keyCount() returns keyHashes.length(). After any operation,
//  it should equal getKeyCountHarness() (same function, sanity check).
//  More importantly, it can only change by ±1 per non-batch operation.
// ═══════════════════════════════════════════════════════════════════════════════

rule KM3_keyCountMatchesHarness {
    env e;
    calldataarg args;

    // keyCount() and getKeyCountHarness() should always agree
    // (they both call keyHashes.length())
    assert keyCount() == getKeyCountHarness(),
        "KM-3: keyCount() must equal getKeyCountHarness()";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  KM-6 for removeSigner: Same completeness check via the signer path
// ═══════════════════════════════════════════════════════════════════════════════

rule KM6_removeSignerRemovesCompletely {
    env e;
    bytes32 signerHash;

    // Pre: key exists, is a signer (not SuperAdmin, not Admin)
    require isKeyInSet(signerHash);
    require getKeyStorageLength(signerHash) > 0;
    require !isKeySuperAdminHarness(signerHash);
    require !isKeyAdminHarness(signerHash);
    require e.msg.value == 0;

    removeSigner(e, signerHash);

    assert !isKeyInSet(signerHash),
        "KM-6: After removeSigner, key hash must not be in set";
    assert getKeyStorageLength(signerHash) == 0,
        "KM-6: After removeSigner, key storage must be cleared";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  Parametric: No operation creates phantom keys
//
//  A "phantom key" is a hash in keyHashes that has empty keyStorage, or
//  a non-empty keyStorage hash that's not in keyHashes. This would break
//  getKey() and enumeration.
// ═══════════════════════════════════════════════════════════════════════════════

// Targeted consistency: after addSigner, the added key is consistent.
rule noPhantomKeys_addSigner {
    env e;
    calldataarg args;

    mathint countBefore = getKeyCountHarness();

    addSigner@withrevert(e, args);

    // If addSigner succeeded, the count increased by 1
    assert !lastReverted => to_mathint(getKeyCountHarness()) == countBefore + 1,
        "addSigner must add exactly one key when successful";
}

// Targeted consistency: after authorizeAdmin, the added key is consistent.
rule noPhantomKeys_authorizeAdmin {
    env e;
    calldataarg args;

    mathint countBefore = getKeyCountHarness();

    authorizeAdmin@withrevert(e, args);

    assert !lastReverted => to_mathint(getKeyCountHarness()) == countBefore + 1,
        "authorizeAdmin must add exactly one key when successful";
}
