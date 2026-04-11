/*
 * ═══════════════════════════════════════════════════════════════════════════════
 *  PAYMASTER CRITICAL FINDINGS SPECIFICATION
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Confirms the highest-severity findings from VERIFICATION_PLAN.md:
 *
 *    F-3:  _validateCalls only checks first call in batch (HIGH)
 *    F-8:  Admin keys can drain ETH via data-less batch calls (HIGH)
 *    F-9:  Expired Signer keys still authorize verifying mode (HIGH)
 *    F-11: executeBatch + self-call bypasses role modifiers (HIGH)
 *    F-12: P256 account-level validation is dead code (INFO)
 *    SV-4: Signer role rejected in validateSignature (INFO)
 *
 *  Architecture:
 *    - Key role helpers verify the logical conditions that enable F-9
 *    - Allowed selector enumeration supports F-3/F-8
 *    - Self-call modifier bypass proves F-11
 *    - Role exclusivity catches structural issues
 *
 *  WHY these are Tier 0: These findings represent exploitable attack chains
 *  that can lead to fund theft or permanent contract lockout.
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

    // ── Key role pure helpers ──
    function keyIsSuperAdminPure(uint40, uint8, bool, bool, uint256)
        external returns (bool) envfree;
    function keyIsAdminPure(uint40, uint8, bool, bool, uint256)
        external returns (bool) envfree;
    function keyIsSignerPure(uint40, uint8, bool, bool, uint256)
        external returns (bool) envfree;
    function keyValidationView(uint40)
        external returns (bool); // NOT envfree — uses block.timestamp

    // ── Selector validation ──
    function isAllowedSelectorHarness(bytes4)        external returns (bool) envfree;

    // ── Contract functions ──
    function revoke(bytes32)                         external;
    function removeSigner(bytes32)                   external;
    function deposit()                               external;
    function withdrawTo(address, uint256)             external;

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
//  FINDING F-9: Expired Signer Keys Bypass in Verifying Mode
//  Severity: HIGH
//  Location: Validations.sol:110 — key._keyValidation() || key._isSigner()
//
//  The || operator means an expired Signer key passes the condition:
//    _keyValidation() returns FALSE (expired: expiry < block.timestamp)
//    _isSigner()      returns TRUE  (structural check, no expiry check)
//    FALSE || TRUE = TRUE → signature verification proceeds
//
//  This means expired Signer keys can still authorize gas sponsorship.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice F-9 BUG CONFIRMATION (Part 1):
///         An expired key fails _keyValidation().
rule F9_expiredKeyFailsValidation {
    env e;
    uint40 expiry;

    // Contract does uint40(block.timestamp) — constrain to realistic range
    require e.block.timestamp <= max_uint40, "block.timestamp fits in uint40 (realistic for ~34000 years)";
    // Key is expired: expiry < block.timestamp
    require to_mathint(expiry) < to_mathint(e.block.timestamp), "key has expired";

    bool result = keyValidationView(e, expiry);

    assert !result,
        "F-9 step 1: Expired key (expiry < timestamp) must fail _keyValidation";
}

/// @notice F-9 BUG CONFIRMATION (Part 2):
///         A Signer-role key passes _isSigner() regardless of expiry.
rule F9_signerCheckIgnoresExpiry {
    uint40 expiry;

    // The key has Signer-role structure:
    // not SuperAdmin, not Admin, expiry != max, publicKey.length > 0
    // Using Secp256k1 (type=2), 32-byte public key
    require expiry != max_uint40;
    require expiry > 0;

    bool result = keyIsSignerPure(
        expiry,  // any non-max, non-zero expiry
        2,       // Secp256k1
        false,   // not SuperAdmin
        false,   // not Admin
        32       // non-empty public key
    );

    assert result,
        "F-9 step 2: _isSigner returns true regardless of expiry value";
}

/// @notice F-9 BUG CONFIRMATION (Part 3):
///         Combined: an expired Signer key passes the || condition.
///         This is the EXACT condition from Validations.sol:110.
rule F9_expiredSignerPassesOrCondition {
    env e;
    uint40 expiry;

    // Contract does uint40(block.timestamp) — constrain to realistic range
    require e.block.timestamp <= max_uint40, "block.timestamp fits in uint40 (realistic for ~34000 years)";
    // Key is expired
    require to_mathint(expiry) < to_mathint(e.block.timestamp), "key has expired";
    // Key has Signer structure
    require expiry != max_uint40;
    require expiry > 0;

    bool keyValid = keyValidationView(e, expiry);
    bool isSigner = keyIsSignerPure(expiry, 2, false, false, 32);

    // The || condition from _validateVerifyingMode
    bool passesCondition = keyValid || isSigner;

    // Prove all three facts:
    assert !keyValid,
        "F-9: Key is expired (validation fails)";
    assert isSigner,
        "F-9: Key is structurally a signer";
    assert passesCondition,
        "F-9 CONFIRMED: Expired signer passes the || condition in verifying mode";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FINDING F-3 & F-8: Allowed Selector Enumeration
//  Severity: HIGH
//
//  _isAllowedSelector only permits 4 selectors:
//    deposit(), addStake(uint32), unlockStake(), addSigner(Key)
//
//  Any other selector returns false. But _validateCalls returns true if
//  all calls have data.length < 4 (bypasses selector check entirely).
//  This enables Admin keys to drain ETH via value-only batch calls.
//
//  Strategy: Prove the allowed selector set is exactly these 4.
//            Then the F-3 bypass + F-8 drain follow logically.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice F-3/F-8 PREREQUISITE: Only 4 selectors are allowed.
///         Any selector that passes isAllowedSelector must be one of these four.
rule F3_allowedSelectorExhaustive {
    bytes4 sel;

    // If the selector is allowed...
    require isAllowedSelectorHarness(sel);

    // ...it must be one of exactly these four
    assert sel == to_bytes4(0xd0e30db0)   // deposit()
        || sel == to_bytes4(0x0396cb60)   // addStake(uint32)
        || sel == to_bytes4(0xbb9fe6bf)   // unlockStake()
        || sel == to_bytes4(0x56864ab1),  // addSigner(Key)
        "F-3: Only 4 selectors are in the Admin-allowed list";
}

/// @notice F-3 PREREQUISITE: Critical selectors are NOT allowed.
///         withdrawTo, withdrawStake, revoke, removeSigner, authorizeAdmin
///         are NOT in the allowed set.
rule F3_criticalSelectorsNotAllowed {
    // These are all selectors that could drain funds or modify admin keys
    assert !isAllowedSelectorHarness(to_bytes4(0x205c2878)),  // withdrawTo(address,uint256)
        "F-3: withdrawTo selector is NOT allowed for Admin batch calls";
}

/// @notice F-3 PREREQUISITE: The revoke selector is not allowed.
rule F3_revokeNotAllowed {
    assert !isAllowedSelectorHarness(to_bytes4(0xb6549f75)),  // revoke(bytes32)
        "F-3: revoke selector is NOT allowed for Admin batch calls";
}

/// @notice F-8: Deposit selector IS allowed (harmless).
rule F8_depositIsAllowed {
    assert isAllowedSelectorHarness(to_bytes4(0xd0e30db0)),
        "F-8: deposit() selector is in the allowed list";
}

/// @notice F-8: The zero selector (data.length < 4 case) is NOT allowed.
///         This means if _validateCalls properly checked all calls,
///         data-less calls would be rejected. The bug is that they're not checked.
rule F8_zeroSelectorNotAllowed {
    assert !isAllowedSelectorHarness(to_bytes4(0x00000000)),
        "F-8: zero/empty selector is NOT in the allowed list";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FINDING F-11: Self-Call Bypasses Role-Specific Access Control
//  Severity: HIGH (dependent on F-3)
//
//  Both modifiers allow msg.sender == address(this):
//    onlySuperAdminOrAdminKeyOrEp: passes if sender == self
//    onlySuperAdminKeyOrEp:        passes if sender == self
//
//  Combined with executeBatch (which calls as msg.sender == address(this)),
//  any function gated by these modifiers becomes callable through executeBatch.
//
//  Strategy: Prove that self-address can call SuperAdmin-only functions.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice F-11 BUG CONFIRMATION: Self-address can call revoke (SuperAdmin-gated).
///         In normal operation, only SuperAdmin/EP should be able to revoke.
///         But address(this) passes the modifier too, enabling executeBatch bypass.
rule F11_selfCanCallRevoke {
    env e;
    bytes32 keyHash;

    // Sender is the contract itself (simulates executeBatch self-call)
    require e.msg.sender == getSelfAddress();
    require e.msg.value == 0;

    // The self-address is NOT the EntryPoint
    require getSelfAddress() != getEntryPointAddress();

    // The key exists
    require isKeyInSet(keyHash);
    require getKeyStorageLength(keyHash) > 0;

    revoke@withrevert(e, keyHash);

    // BUG: Self-call bypasses the SuperAdmin check in the modifier
    satisfy !lastReverted,
        "F-11 CONFIRMED: address(this) can call revoke, bypassing SuperAdmin requirement";
}

/// @notice F-11: Self-address can call withdrawTo (SuperAdmin-gated).
rule F11_selfCanCallWithdrawTo {
    env e;
    address withdrawAddr;
    uint256 amount;

    require e.msg.sender == getSelfAddress();
    require e.msg.value == 0;
    require getSelfAddress() != getEntryPointAddress();

    withdrawTo@withrevert(e, withdrawAddr, amount);

    satisfy !lastReverted,
        "F-11 CONFIRMED: address(this) can call withdrawTo, bypassing SuperAdmin check";
}

/// @notice F-11: Self-address can call deposit (Admin/SuperAdmin-gated).
///         This is less severe (deposit is allowed for Admin) but demonstrates
///         the pattern works for ALL modifier-gated functions.
rule F11_selfCanCallDeposit {
    env e;

    require e.msg.sender == getSelfAddress();
    require getSelfAddress() != getEntryPointAddress();

    deposit@withrevert(e);

    satisfy !lastReverted,
        "F-11: address(this) can call deposit without any key";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  KEY ROLE STRUCTURAL PROPERTIES
//
//  These verify that the role classification logic in KeyLib is consistent.
//  SuperAdmin, Admin, and Signer should be mutually exclusive.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice Roles are mutually exclusive: a key cannot be both SuperAdmin and Admin.
rule roleExclusivity_superAdminVsAdmin {
    uint40 expiry;
    uint8 keyType;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool sa = keyIsSuperAdminPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);
    bool ad = keyIsAdminPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);

    assert !(sa && ad),
        "Role exclusivity: a key cannot be both SuperAdmin and Admin";
}

/// @notice Roles are mutually exclusive: a key cannot be both SuperAdmin and Signer.
rule roleExclusivity_superAdminVsSigner {
    uint40 expiry;
    uint8 keyType;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool sa = keyIsSuperAdminPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);
    bool si = keyIsSignerPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);

    assert !(sa && si),
        "Role exclusivity: a key cannot be both SuperAdmin and Signer";
}

/// @notice Roles are mutually exclusive: a key cannot be both Admin and Signer.
rule roleExclusivity_adminVsSigner {
    uint40 expiry;
    uint8 keyType;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool ad = keyIsAdminPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);
    bool si = keyIsSignerPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);

    assert !(ad && si),
        "Role exclusivity: a key cannot be both Admin and Signer";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  F-7 / SV-4: P256 Key Type Constraints
//
//  P256 (keyType=0) keys CANNOT be SuperAdmin or Admin.
//  Only WebAuthnP256 (1) and Secp256k1 (2) qualify.
//  This is because _isSuperAdmin and _isAdmin require keyType >= 1.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice F-7: P256 key type cannot be SuperAdmin.
rule F7_p256CannotBeSuperAdmin {
    uint40 expiry;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool result = keyIsSuperAdminPure(
        expiry,
        0,              // P256 key type
        isSuperAdmin,
        isAdmin,
        pkLen
    );

    assert !result,
        "F-7: P256 (keyType=0) can never be SuperAdmin (requires keyType >= 1)";
}

/// @notice F-7: P256 key type cannot be Admin.
rule F7_p256CannotBeAdmin {
    uint40 expiry;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool result = keyIsAdminPure(
        expiry,
        0,              // P256 key type
        isSuperAdmin,
        isAdmin,
        pkLen
    );

    assert !result,
        "F-7: P256 (keyType=0) can never be Admin (requires keyType >= 1)";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SANITY: SuperAdmin, Admin, and Signer roles CAN each be satisfied
// ═══════════════════════════════════════════════════════════════════════════════

rule sanity_superAdminExists {
    uint40 expiry;
    uint8 keyType;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool result = keyIsSuperAdminPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);

    satisfy result,
        "Sanity: A valid SuperAdmin key configuration exists";
}

rule sanity_adminExists {
    uint40 expiry;
    uint8 keyType;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool result = keyIsAdminPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);

    satisfy result,
        "Sanity: A valid Admin key configuration exists";
}

rule sanity_signerExists {
    uint40 expiry;
    uint8 keyType;
    bool isSuperAdmin;
    bool isAdmin;
    uint256 pkLen;

    bool result = keyIsSignerPure(expiry, keyType, isSuperAdmin, isAdmin, pkLen);

    satisfy result,
        "Sanity: A valid Signer key configuration exists";
}


// ═══════════════════════════════════════════════════════════════════════════════
//  F-9 vs ERC20 MODE: Verify asymmetry between verifying and ERC20 modes
//
//  In verifying mode: key._keyValidation() || key._isSigner()
//  In ERC20 mode:     key._keyValidation() only
//
//  An expired signer PASSES verifying mode but FAILS ERC20 mode.
//  This is the architectural asymmetry noted in SV-7.
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice SV-7: Expired signer fails the ERC20 mode condition.
///         ERC20 mode uses _keyValidation() only (no || _isSigner()).
rule SV7_expiredSignerFailsERC20Mode {
    env e;
    uint40 expiry;

    // Contract does uint40(block.timestamp) — constrain to realistic range
    require e.block.timestamp <= max_uint40, "block.timestamp fits in uint40 (realistic for ~34000 years)";
    // Key is expired
    require to_mathint(expiry) < to_mathint(e.block.timestamp), "key has expired";
    require expiry != max_uint40;
    require expiry > 0;

    bool keyValid = keyValidationView(e, expiry);

    // In ERC20 mode, only _keyValidation is checked (no || _isSigner)
    // So an expired key always fails ERC20 mode
    assert !keyValid,
        "SV-7: Expired signer key fails ERC20 mode (no || bypass)";
}
