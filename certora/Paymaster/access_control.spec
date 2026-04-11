/*
 * ═══════════════════════════════════════════════════════════════════════════════
 *  PAYMASTER ACCESS CONTROL SPECIFICATION
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Verifies: AC-1 through AC-10 from VERIFICATION_PLAN.md
 *
 *  Architecture:
 *    - One parametric rule covers ALL non-view functions (fully unauthorized sender)
 *    - Individual rules cover role-specific constraints (AC-8 KillSwitch, etc.)
 *    - Sanity rules (satisfy) confirm non-vacuity
 *
 *  WHY these properties matter:
 *    Unauthorized access to key management or fund withdrawal = total compromise.
 *    These are Tier 1 verification targets.
 *
 *  NOTE on munging: EfficientHashLib is replaced with a pure-Solidity version
 *  (certora/Paymaster/munged/EfficientHashLib.sol) to enable Certora's static
 *  analysis. The assembly-based original causes "failed to compute per-call stats".
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ─── Methods Block ───────────────────────────────────────────────────────────

methods {
    // ── Harness getters (envfree = no tx context needed) ──
    function getEntryPointAddress()                 external returns (address)  envfree;
    function getSelfAddress()                       external returns (address)  envfree;
    function isKeySuperAdminHarness(bytes32)         external returns (bool)    envfree;
    function isKeyAdminHarness(bytes32)              external returns (bool)    envfree;
    function getKeyStorageLength(bytes32)            external returns (uint256) envfree;
    function isKeyInSet(bytes32)                     external returns (bool)    envfree;
    function getKeyCountHarness()                    external returns (uint256) envfree;
    function hashAddressHarness(address)             external returns (bytes32) envfree;
    function senderHasNoKey(address)                 external returns (bool)    envfree;

    // ── Contract state-changing functions (need env) ──
    function deposit()                              external;
    function withdrawTo(address, uint256)            external;
    function addStake(uint32)                        external;
    function unlockStake()                           external;
    function withdrawStake(address)                  external;
    function removeSigner(bytes32)                   external;
    function revoke(bytes32)                         external;
    function keyCount()                              external returns (uint256) envfree;

    // ── External call summaries ──
    // EntryPoint interactions — we don't model their internals
    function _.depositTo(address)           external => NONDET;
    function _.withdrawTo(address, uint256) external => NONDET;
    function _.addStake(uint32)             external => NONDET;
    function _.unlockStake()                external => NONDET;
    function _.withdrawStake(address)       external => NONDET;
    function _.balanceOf(address)           external => NONDET;

    // WebAuthn verifier — signature outcome is nondeterministic
    function _.verifyP256Signature(bytes32, bytes32, bytes32, bytes32, bytes32)
        external => NONDET;
    function _.verifyEncodedSignature(bytes32, bool, bytes, bytes32, bytes32)
        external => NONDET;

    // Token transfers — summarized to prevent havoc on ERC20 calls
    function _.safeTransferFrom(address, address, address, uint256) external => NONDET;
    function _.transferFrom(address, address, uint256) external => NONDET;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  AC-1 to AC-7 (combined): No fully-unauthorized caller can execute ANY
//  state-changing function.
//
//  "Fully unauthorized" = not EntryPoint, not self, and has no registered key.
//
//  Uses senderHasNoKey(address) which wraps the hash + storage lookup in
//  a single Solidity call, avoiding exposing EfficientHashLib to CVL directly.
// ═══════════════════════════════════════════════════════════════════════════════

rule AC_noCallByFullyUnauthorized(method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    // Sender is NOT any authorized entity
    require e.msg.sender != getEntryPointAddress();
    require e.msg.sender != getSelfAddress();
    // Sender has NO registered key (not SuperAdmin, not Admin, not Signer)
    require senderHasNoKey(e.msg.sender);

    f@withrevert(e, args);

    assert lastReverted,
        "AC-1..7: Fully unauthorized callers must be rejected from all state-changing functions";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  AC-8: KillSwitch — removeSigner MUST revert for SuperAdmin/Admin keys
//
//  WHY: The KillSwitch prevents admin keys from being removed through the
//  signer removal path. Without this, an attacker could downgrade key roles.
//  MultiSigner.sol:33 enforces this check.
// ═══════════════════════════════════════════════════════════════════════════════

rule AC8_removeSigner_cannotRemoveSuperAdmin {
    env e;
    bytes32 keyHash;

    // Preconditions: the key exists and IS a SuperAdmin
    require isKeySuperAdminHarness(keyHash);
    require isKeyInSet(keyHash);
    require getKeyStorageLength(keyHash) > 0;
    require e.msg.value == 0;

    removeSigner@withrevert(e, keyHash);

    assert lastReverted,
        "AC-8: removeSigner must revert when target key is SuperAdmin (KillSwitch)";
}

rule AC8_removeSigner_cannotRemoveAdmin {
    env e;
    bytes32 keyHash;

    // Preconditions: the key exists and IS an Admin
    require isKeyAdminHarness(keyHash);
    require isKeyInSet(keyHash);
    require getKeyStorageLength(keyHash) > 0;
    require e.msg.value == 0;

    removeSigner@withrevert(e, keyHash);

    assert lastReverted,
        "AC-8: removeSigner must revert when target key is Admin (KillSwitch)";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  AC-5: addSigner requires SuperAdmin/Admin/EP/self
//  Verify that an Admin CAN call addSigner (positive test).
// ═══════════════════════════════════════════════════════════════════════════════

rule AC5_addSigner_adminCanCall {
    env e;
    calldataarg args;

    bytes32 senderHash = hashAddressHarness(e.msg.sender);

    // Sender has an Admin key
    require isKeyAdminHarness(senderHash);
    require getKeyStorageLength(senderHash) > 0;
    require e.msg.value == 0;

    addSigner@withrevert(e, args);

    // Admin CAN call addSigner (may still revert for other reasons like bad input)
    satisfy !lastReverted,
        "AC-5 sanity: Admin can successfully add a signer";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  AC-6: removeSigner requires SuperAdmin/EP/self (NOT Admin)
// ═══════════════════════════════════════════════════════════════════════════════

rule AC6_removeSigner_adminCannotCall {
    env e;
    bytes32 signerHash;

    bytes32 senderHash = hashAddressHarness(e.msg.sender);

    // Sender is Admin (not SuperAdmin, not EP, not self)
    require isKeyAdminHarness(senderHash);
    require !isKeySuperAdminHarness(senderHash);
    require e.msg.sender != getEntryPointAddress();
    require e.msg.sender != getSelfAddress();
    require e.msg.value == 0;

    removeSigner@withrevert(e, signerHash);

    assert lastReverted,
        "AC-6: Admin (non-SuperAdmin) cannot call removeSigner";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  AC-7: withdrawTo requires SuperAdmin/EP/self (NOT Admin)
// ═══════════════════════════════════════════════════════════════════════════════

rule AC7_withdrawTo_adminCannotCall {
    env e;
    address withdrawAddr;
    uint256 amount;

    bytes32 senderHash = hashAddressHarness(e.msg.sender);

    // Sender is Admin only (not SuperAdmin, not EP, not self)
    require isKeyAdminHarness(senderHash);
    require !isKeySuperAdminHarness(senderHash);
    require e.msg.sender != getEntryPointAddress();
    require e.msg.sender != getSelfAddress();
    require e.msg.value == 0;

    withdrawTo@withrevert(e, withdrawAddr, amount);

    assert lastReverted,
        "AC-7: Admin (non-SuperAdmin) cannot call withdrawTo";
}

rule AC7_withdrawStake_adminCannotCall {
    env e;
    address withdrawAddr;

    bytes32 senderHash = hashAddressHarness(e.msg.sender);

    require isKeyAdminHarness(senderHash);
    require !isKeySuperAdminHarness(senderHash);
    require e.msg.sender != getEntryPointAddress();
    require e.msg.sender != getSelfAddress();
    require e.msg.value == 0;

    withdrawStake@withrevert(e, withdrawAddr);

    assert lastReverted,
        "AC-7: Admin (non-SuperAdmin) cannot call withdrawStake";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  AC-9: authorizeAdmin — if it succeeds, exactly one key was added.
// ═══════════════════════════════════════════════════════════════════════════════

rule AC9_authorizeAdmin_addsExactlyOneKey {
    env e;
    calldataarg args;

    require e.msg.value == 0, "authorizeAdmin is non-payable";

    mathint countBefore = getKeyCountHarness();

    authorizeAdmin@withrevert(e, args);

    assert !lastReverted => to_mathint(getKeyCountHarness()) == countBefore + 1,
        "AC-9: Successful authorizeAdmin must add exactly one key";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  Parametric: Key count only changes by +/-1 per single operation.
//  executeBatch is excluded — it can make multiple key changes in a batch,
//  which is the F-11 self-call escalation path we document separately.
// ═══════════════════════════════════════════════════════════════════════════════

// NOTE on exclusions:
//   executeBatch: EXCLUDED because violation CONFIRMS F-11 (self-call key escalation)
//   postOp: EXCLUDED because havoc on _getCostInToken DELEGATECALL (false positive)
//   validatePaymasterUserOp: EXCLUDED because havoc on webAuthnVerifier call (false positive)
//   validateUserOp: EXCLUDED because havoc on signature verification calls (false positive)
// These functions do NOT modify key storage — only key management functions do.
rule keyCountChangesBoundedByOne(method f) filtered {
    f -> !f.isView
      && f.selector != 0x34fcd5be // executeBatch
      && f.selector != 0x7c627b21 // postOp(uint8,bytes,uint256,uint256)
      && f.selector != 0x52b7512c // validatePaymasterUserOp (from AA EntryPoint)
      && f.selector != 0x19822f7c // validateUserOp (from AA EntryPoint)
} {
    env e;
    calldataarg args;

    mathint countBefore = getKeyCountHarness();

    f(e, args);

    mathint countAfter = getKeyCountHarness();

    assert countAfter == countBefore
        || countAfter == countBefore + 1
        || countAfter == countBefore - 1,
        "Key count should change by at most 1 per function call";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  Sanity checks
// ═══════════════════════════════════════════════════════════════════════════════

rule sanity_depositCanSucceed {
    env e;

    require e.msg.sender == getEntryPointAddress();

    deposit@withrevert(e);

    satisfy !lastReverted,
        "Sanity: deposit can succeed when called by EntryPoint";
}

rule sanity_revokeCanSucceed {
    env e;
    bytes32 keyHash;

    require e.msg.sender == getEntryPointAddress();
    require e.msg.value == 0;
    require isKeyInSet(keyHash);
    require getKeyStorageLength(keyHash) > 0;

    revoke@withrevert(e, keyHash);

    satisfy !lastReverted,
        "Sanity: revoke can succeed when called by EntryPoint on existing key";
}
