# Paymaster Formal Verification Plan

## Contract Architecture Overview

The Paymaster is an ERC-4337 account-abstraction paymaster system with multi-signer key management, supporting both verifying mode (gas sponsorship) and ERC-20 token payment mode.

### Inheritance Chain

```
Storage (state variables: entryPoint, webAuthnVerifier, signers, isBundlerAllowed, keyHashes, keyStorage)
  -> ManagerAccessControl (access control modifiers)
    -> KeysManager (key CRUD: addKey, removeKey, getKey, revoke)
      -> MultiSigner (addSigner, removeSigner with role checks)
        -> BasePaymaster (validateUserOp, deposit, withdraw, stake, executeBatch)
          -> Validations (validatePaymasterUserOp, postOp, signature validation, ERC20 mode)
            -> Paymaster (getHash override with EIP-7702 support)
              -> PaymasterEntry (constructor, concrete deployment)
```

### State Variables (from Storage.sol)

| Variable | Type | Purpose |
|----------|------|---------|
| `entryPoint` | `IEntryPoint` (immutable) | ERC-4337 EntryPoint address |
| `webAuthnVerifier` | `IWebAuthnVerifier` (immutable) | WebAuthn signature verifier |
| `signers` | `mapping(address => bool)` | Legacy signer mapping (unused in current code) |
| `isBundlerAllowed` | `mapping(address => bool)` | Allowlisted bundlers |
| `keyHashes` | `EnumerableSetLib.Bytes32Set` | Set of authorized key hashes |
| `keyStorage` | `mapping(bytes32 => LibBytes.BytesStorage)` | Key hash -> encoded key data |

### Key Roles (from Key struct + KeyLib)

| Role | isSuperAdmin | isAdmin | expiry | keyType |
|------|-------------|---------|--------|---------|
| SuperAdmin | true | false | `type(uint40).max` | >= 1 (WebAuthn or Secp256k1) |
| Admin | false | true | != `type(uint40).max` | >= 1 |
| Signer | false | false | != `type(uint40).max` | any |

### External Functions (attack surface)

| Function | Access Control | Mutates State | Moves Funds |
|----------|---------------|---------------|-------------|
| `validateUserOp` | EntryPoint only | No (view override) | Yes (`_payPrefund`) |
| `validatePaymasterUserOp` | EntryPoint only | Yes (token transfers) | Yes (ERC20 mode) |
| `postOp` | EntryPoint only | Yes (token transfers) | Yes |
| `executeBatch` | EntryPoint only | Yes (arbitrary calls) | Yes |
| `deposit` | SuperAdmin/Admin/EP | Yes (ETH to EP) | Yes |
| `withdrawTo` | SuperAdmin/EP | Yes (ETH from EP) | Yes |
| `addStake` | SuperAdmin/Admin/EP | Yes (ETH to EP) | Yes |
| `unlockStake` | SuperAdmin/Admin/EP | Yes | No |
| `withdrawStake` | SuperAdmin/EP | Yes | Yes |
| `addSigner` | SuperAdmin/Admin/EP | Yes (keyStorage) | No |
| `removeSigner` | SuperAdmin/EP | Yes (keyStorage) | No |
| `authorizeAdmin` | SuperAdmin/EP | Yes (keyStorage) | No |
| `revoke` | SuperAdmin/EP | Yes (keyStorage) | No |

---

## Phase 2: Property Extraction (The 8 Categories)

### Category 1: Access Control Properties (CRITICAL PRIORITY)

These are the most important properties. Unauthorized access to key management or funds = total compromise.

#### AC-1: Only EntryPoint can call validateUserOp
```
validateUserOp MUST revert if msg.sender != entryPoint
```
**Why:** If anyone can call validateUserOp, they can trigger _payPrefund and drain ETH.

#### AC-2: Only EntryPoint can call validatePaymasterUserOp
```
validatePaymasterUserOp MUST revert if msg.sender != entryPoint
```
**Why:** This function triggers ERC-20 token transfers in ERC20 mode.

#### AC-3: Only EntryPoint can call postOp
```
postOp MUST revert if msg.sender != entryPoint
```
**Why:** postOp performs token transfers based on gas accounting.

#### AC-4: Only EntryPoint can call executeBatch
```
executeBatch MUST revert if msg.sender != entryPoint
```
**Why:** executeBatch can make arbitrary external calls with the paymaster's identity.

#### AC-5: Only SuperAdmin or Admin can add signers
```
addSigner MUST revert if msg.sender is not SuperAdmin, Admin, EntryPoint, or self
```

#### AC-6: Only SuperAdmin can remove signers
```
removeSigner MUST revert if msg.sender is not SuperAdmin, EntryPoint, or self
```

#### AC-7: Only SuperAdmin can withdraw funds
```
withdrawTo MUST revert if msg.sender is not SuperAdmin, EntryPoint, or self
withdrawStake MUST revert if msg.sender is not SuperAdmin, EntryPoint, or self
```

#### AC-8: SuperAdmin and Admin keys cannot be removed via removeSigner
```
removeSigner(_keyHash) MUST revert if keyStorage[_keyHash] is SuperAdmin or Admin
```
**Why:** This is the KillSwitch protection. Removing admin keys through the signer removal path would bypass the proper revocation flow.

#### AC-9: authorizeAdmin can only add Admin keys (not SuperAdmin)
```
authorizeAdmin(_key) MUST revert if _key.isSuperAdmin == true
authorizeAdmin(_key) MUST revert if _key.isAdmin == false
```

#### AC-10: addSigner cannot add Admin or SuperAdmin keys
```
addSigner(_key) MUST revert if _key.isSuperAdmin == true
addSigner(_key) MUST revert if _key.isAdmin == true
```

#### AC-11: Bundler allowlist enforcement
```
_validatePaymasterUserOp MUST revert if allowAllBundlers == false AND isBundlerAllowed[tx.origin] == false
```

---

### Category 2: Key Management Invariants (HIGH PRIORITY)

#### KM-1: Key hash set and storage consistency
```
INVARIANT: For every hash in keyHashes, keyStorage[hash].length() > 0
INVARIANT: For every hash where keyStorage[hash].length() > 0, hash is in keyHashes
```
**Why:** If these diverge, getKey() reverts for existing keys, or phantom keys exist in storage.

#### KM-2: No duplicate key hashes
```
_addKey MUST revert if the key hash already exists in keyHashes
```
**Why:** EnumerableSetLib.add() returns false for duplicates but the contract doesn't check the return value in _addKey. However, addSigner and authorizeAdmin check keyHashes.contains() first. The constructor does NOT check - potential issue.

#### KM-3: keyCount() accuracy
```
INVARIANT: keyCount() == number of keys added - number of keys removed
```

#### KM-4: At least one SuperAdmin must always exist
```
After any sequence of revoke() calls, there must be at least one SuperAdmin key remaining.
```
**FINDING: The contract does NOT enforce this.** revoke() has no check preventing removal of the last SuperAdmin. This could lock the contract permanently.

#### KM-5: Key encoding/decoding round-trip
```
For any Key k: getKey(_addKey(k)) should return a Key equivalent to k
```
**Why:** The encoding packs publicKey + expiry + keyType + isSuperAdmin + isAdmin into bytes. The decoding in getKey() must extract the same values.

#### KM-6: Removing a key clears it completely
```
After revoke(hash): keyStorage[hash].length() == 0 AND hash is not in keyHashes
```

---

### Category 3: Signature Validation Properties (HIGH PRIORITY)

#### SV-1: Invalid signatures must return SIG_VALIDATION_FAILED
```
If the signature is not valid for the given hash, validationData must encode sigFailed = true
```

#### SV-2: Valid SuperAdmin signature returns SUCCESS in verifying mode
```
If signerType == Secp256k1 AND recovered signer is a non-expired SuperAdmin key:
  validationData encodes sigFailed = false
```

#### SV-3: Valid Admin signature requires valid calldata in verifying mode
```
If signerType == Secp256k1 AND recovered signer is Admin:
  validationData == SUCCESS only if _validateCallData returns true
```

#### SV-4: Signer role keys ALWAYS return FAILED in validateSignature
```
In _validateWebAuthnSigner: if key._isSigner() return SIG_VALIDATION_FAILED
In _validateSecp256k1Signer: if key._isSigner() return SIG_VALIDATION_FAILED
```
**IMPORTANT: This is counterintuitive.** The "signer" role keys are used for paymaster validation (validatePaymasterUserOp), NOT for validateUserOp/validateSignature. In validateSignature, only SuperAdmin and Admin keys are accepted. Signer keys are explicitly rejected.

#### SV-5: Unknown signer types revert
```
_validateSignature MUST revert if signerType > 2
```

#### SV-6: Expired keys must not validate
```
If key.expiry < block.timestamp, _keyValidation returns false, and the signature must fail
```

#### SV-7: Verifying mode vs ERC20 mode role differences
```
Verifying mode: accepts SuperAdmin, Admin, AND Signer keys (key._keyValidation() || key._isSigner())
ERC20 mode: accepts ONLY SuperAdmin and Admin keys (key._keyValidation() only)
```
**FINDING: This asymmetry is intentional but should be verified.** In verifying mode (Validations.sol:110), the condition is `key._keyValidation() || key._isSigner()`. In ERC20 mode (Validations.sol:155), it's only `key._keyValidation()`. This means Signer-role keys can authorize gas sponsorship but NOT ERC20 token payments.

---

### Category 4: Funds Flow Properties (CRITICAL PRIORITY)

#### FF-1: _payPrefund sends exactly missingAccountFunds
```
If missingAccountFunds > 0, exactly missingAccountFunds wei is sent to msg.sender (EntryPoint)
If missingAccountFunds == 0, no ETH is sent
```

#### FF-2: deposit() forwards exact msg.value to EntryPoint
```
deposit() calls entryPoint.depositTo{value: msg.value}(address(this))
The paymaster's deposit balance in EntryPoint increases by msg.value
```

#### FF-3: withdrawTo sends to specified address only
```
withdrawTo(_addr, _amount) calls entryPoint.withdrawTo(_addr, _amount)
Only the specified _withdrawAddress receives funds
```

#### FF-4: ERC20 mode preFund validation
```
If cfg.preFundInToken > costInToken: MUST revert with PreFundTooHigh
```
**Why:** Prevents overcharging users on pre-funding.

#### FF-5: ERC20 preFund token transfer correctness
```
If preFundInToken > 0 AND signature is valid:
  safeTransferFrom(token, userOp.sender, treasury, preFundInToken) is called
```

#### FF-6: postOp settlement direction
```
If costInToken > preFundCharged:
  Transfer (costInToken - preFundCharged) FROM sender TO treasury (user owes more)
If preFundCharged > costInToken:
  Transfer (preFundCharged - costInToken) FROM treasury TO sender (refund)
If costInToken == preFundCharged:
  Transfer 0 tokens (no-op effectively, but transfer still called)
```
**FINDING: When costInToken == preFundCharged, absoluteCostInToken = 0, but the transfer still executes with amount 0. The direction is treasury->sender (since costInToken > preFundCharged is false). This is a zero-value transfer but wastes gas.**

#### FF-7: Recipient surplus distribution
```
If ctx.recipient != address(0) AND preFundInToken > costInToken:
  safeTransferFrom(token, sender, recipient, preFundInToken - costInToken)
```

#### FF-8: No ETH stuck in paymaster
```
INVARIANT: The paymaster contract's ETH balance should only change through deposit/withdraw flows
```

---

### Category 5: Parsing and Encoding Properties (MEDIUM PRIORITY)

#### PE-1: _parsePaymasterAndData minimum length
```
MUST revert if paymasterAndData.length < paymasterDataOffset + 1
```

#### PE-2: Mode extraction correctness
```
mode = (combinedByte >> 1)
allowAllBundlers = (combinedByte & 0x01) != 0
```
**Note:** mode can be 0-127 (7 bits after shift). Only 0 (VERIFYING) and 1 (ERC20) are valid.

#### PE-3: Invalid mode rejection
```
MUST revert if mode != VERIFYING_MODE AND mode != ERC20_MODE
```

#### PE-4: _parseVerifyingConfig minimum length
```
MUST revert if paymasterConfig.length < VERIFYING_PAYMASTER_DATA_LENGTH (12 bytes)
```

#### PE-5: _parseErc20Config minimum length
```
MUST revert if paymasterConfig.length < ERC20_PAYMASTER_DATA_LENGTH (117 bytes)
```

#### PE-6: ERC20 config validation
```
MUST revert if token == address(0)
MUST revert if exchangeRate == 0
MUST revert if recipientPresent AND recipient == address(0)
MUST revert if signerType > max(SignerType)
```

#### PE-7: _getCostInToken arithmetic correctness
```
_getCostInToken(actualGasCost, postOpGas, feePerGas, exchangeRate) ==
  ((actualGasCost + (postOpGas * feePerGas)) * exchangeRate) / 1e18
```
**FINDING: Potential overflow.** `actualGasCost + (postOpGas * feePerGas)` can be very large. Multiplying by exchangeRate (uint256) could overflow. Solidity 0.8.34 will revert on overflow, but this means valid operations could fail with large gas costs and high exchange rates.

#### PE-8: _expectedPenaltyGasCost division by zero
```
If _actualUserOpFeePerGas == 0:
  _actualGasCost / _actualUserOpFeePerGas will revert (division by zero)
```
**FINDING: No guard against _actualUserOpFeePerGas == 0.** The EntryPoint should never pass 0, but the contract doesn't defend against it. If it somehow receives 0, the entire postOp reverts, which could lock user funds in the paymaster.

#### PE-9: Penalty gas calculation correctness
```
actualGas = _actualGasCost / _actualUserOpFeePerGas + _postOpGas
executionGasUsed = max(0, actualGas - _preOpGasApproximation)
expectedPenaltyGas = max(0, (_executionGasLimit - executionGasUsed) * PENALTY_PERCENT / 100)
return expectedPenaltyGas * _actualUserOpFeePerGas
```

---

### Category 6: State Transition Properties

#### ST-1: addSigner only modifies keyStorage and keyHashes
```
After addSigner(key):
  keyStorage[key.hash()].length() > 0
  keyHashes.contains(key.hash()) == true
  No other state variables changed
```

#### ST-2: removeSigner only modifies keyStorage and keyHashes
```
After removeSigner(hash):
  keyStorage[hash].length() == 0
  keyHashes.contains(hash) == false
  No other state variables changed
```

#### ST-3: isBundlerAllowed only set in constructor
```
INVARIANT: isBundlerAllowed mapping cannot change after construction
```
**FINDING: There is no function to add or remove bundlers post-deployment.** The bundler allowlist is set once in the constructor and is immutable. This means if a bundler needs to be added or removed, a new paymaster must be deployed. This may be intentional but limits operational flexibility.

---

### Category 7: Revert Condition Properties

#### RC-1: executeBatch propagates reverts correctly
```
If calls.length == 1 AND the call fails: revert with the call's return data
If calls.length > 1 AND a call fails: revert with ExecuteError(index, returnData)
```

#### RC-2: Constructor must revert on invalid inputs
```
MUST revert if superAdmin key is not a valid SuperAdmin
MUST revert if admin key is not a valid Admin
MUST revert if any signer is not a valid Signer
MUST revert if entryPoint == address(0)
MUST revert if webAuthnVerifier == address(0)
MUST revert if any allowedBundler == address(0)
```

---

### Category 8: No Side Effects Properties

#### NSE-1: View functions don't modify state
```
getHash, getKey, getKeys, keyCount, keyAt, getDeposit are all pure/view
```

#### NSE-2: Failed signature validation doesn't modify state
```
If _validateSignature returns SIG_VALIDATION_FAILED, no state was changed
```

#### NSE-3: validatePaymasterUserOp in verifying mode has no token side effects
```
In VERIFYING_MODE: no safeTransferFrom calls are made
Context returned is empty ("")
```

---

## Phase 3: Spec Architecture Design

### Ghost Variables Needed

```
ghost mathint sumKeyCount — tracks total keys (compare with keyCount())
ghost mapping(bytes32 => bool) ghostKeyExists — shadow of keyHashes.contains()
ghost bool entryPointCalled — tracks if entryPoint received calls
```

### Hooks Needed

```
hook Sstore keyStorage[KEY bytes32 h] ... — track key additions/removals
hook Sstore keyHashes ... — track set membership changes
```

**Note:** EnumerableSetLib uses complex internal storage layout. Hooking on it directly may be challenging. May need to hook on the raw storage slots or use a harness.

### Harness Requirements

The contract has deep inheritance and complex dependencies. A harness contract will likely be needed to:

1. Expose internal functions for direct testing
2. Simplify external contract interactions (EntryPoint, WebAuthnVerifier)
3. Provide getter functions for internal state
4. Mock the EntryPoint to control msg.sender in tests

```solidity
contract PaymasterHarness is PaymasterEntry {
    // Expose internal state for verification
    function getKeyStorageLength(bytes32 hash) external view returns (uint256) {
        return keyStorage[hash].length();
    }

    function isKeyInSet(bytes32 hash) external view returns (bool) {
        return keyHashes.contains(hash);
    }

    // Simplified constructor or initialization
}
```

### Linking Strategy

| Contract | Strategy |
|----------|----------|
| IEntryPoint | Link to a simplified mock or use dispatcher |
| IWebAuthnVerifier | Link to a simplified mock (return true/false) |
| ECDSA (OpenZeppelin) | Link directly (pure library) |
| SafeTransferLib | Link directly or summarize |

---

## Verification Priority (Triage)

### Tier 1: MUST VERIFY (funds + access control)

| ID | Property | Estimated Difficulty |
|----|----------|---------------------|
| AC-1 | Only EP calls validateUserOp | Easy |
| AC-2 | Only EP calls validatePaymasterUserOp | Easy |
| AC-3 | Only EP calls postOp | Easy |
| AC-4 | Only EP calls executeBatch | Easy |
| AC-5 | Only SuperAdmin/Admin adds signers | Medium |
| AC-6 | Only SuperAdmin removes signers | Medium |
| AC-7 | Only SuperAdmin withdraws | Medium |
| AC-8 | Cannot remove SuperAdmin/Admin via removeSigner | Easy |
| FF-4 | preFund <= costInToken enforcement | Medium |
| FF-6 | postOp settlement direction | Hard |

### Tier 2: SHOULD VERIFY (state consistency)

| ID | Property | Estimated Difficulty |
|----|----------|---------------------|
| KM-1 | keyHashes <-> keyStorage consistency | Hard (needs ghost+hook) |
| KM-5 | Key encode/decode round-trip | Medium |
| SV-4 | Signer role rejected in validateSignature | Medium |
| SV-6 | Expired keys fail validation | Medium |
| SV-7 | Verifying vs ERC20 role differences | Medium |
| PE-7 | _getCostInToken arithmetic | Easy (pure function) |
| PE-9 | Penalty gas calculation | Easy (pure function) |

### Tier 3: NICE TO VERIFY (edge cases)

| ID | Property | Estimated Difficulty |
|----|----------|---------------------|
| AC-9 | authorizeAdmin role constraints | Easy |
| AC-10 | addSigner role constraints | Easy |
| PE-1 | parsePaymasterAndData length check | Easy |
| PE-6 | ERC20 config validation | Medium |
| RC-1 | executeBatch error propagation | Hard |
| ST-3 | Bundler list immutability | Medium (parametric) |

---

## Potential Bugs and Findings

### FINDING-1: No protection against removing last SuperAdmin (KM-4)
**Severity: HIGH**
**Location:** `KeysManager.sol:revoke()` and `MultiSigner.sol:removeSigner()`

`revoke()` has no check for whether the key being removed is the last SuperAdmin. While `removeSigner()` prevents removing SuperAdmin/Admin keys (KillSwitch), `revoke()` itself is callable by SuperAdmin and has no such guard. A SuperAdmin can revoke their own key, potentially locking the contract.

**Verification approach:** Write a rule that proves after any call to revoke(), at least one SuperAdmin key still exists. If this fails, it confirms the bug.

### FINDING-2: Constructor doesn't check for duplicate keys
**Severity: MEDIUM**
**Location:** `PaymasterEntry.sol:constructor`

The constructor calls `_addKey()` for superAdmin, admin, and all signers. `_addKey()` calls `keyHashes.add()` which is a no-op for duplicates (returns false but doesn't revert). If the same key is passed as both superAdmin and a signer, it would be encoded with the LAST role written, silently overwriting the superAdmin encoding.

**Verification approach:** Prove that after construction, the superAdmin key hash maps to a key where isSuperAdmin == true.

### FINDING-3: _validateCalls only checks FIRST call in batch
**Severity: HIGH**
**Location:** `Validations.sol:_validateCalls()` lines 421-438

The loop iterates over calls, but on the FIRST iteration:
- If `data.length >= 4` and selector is APPROVE_SEL: returns immediately (line 429)
- If selector is not APPROVE_SEL: returns `_isAllowedSelector()` immediately (line 431)
- If `data.length < 4`: falls through to next iteration

The `return` statements inside the loop mean only the FIRST call with data >= 4 bytes is ever checked. All subsequent calls are unchecked.

**Impact:** An Admin key could construct a batch where the first call is an allowed selector, but subsequent calls perform unauthorized actions.

**Verification approach:** Write a parametric rule showing that executeBatch can execute calls with disallowed selectors when the first call has an allowed selector.

### FINDING-4: postOp zero-cost transfer (FF-6)
**Severity: LOW**
**Location:** `Validations.sol:_postOp()` lines 239-247

When `costInToken == preFundCharged`, `absoluteCostInToken = 0`. The code still executes `safeTransferFrom` with amount 0. The direction defaults to treasury->sender (refund path). This wastes gas on a no-op transfer.

### FINDING-5: Division by zero in _expectedPenaltyGasCost (PE-8)
**Severity: MEDIUM**
**Location:** `Validations.sol:_expectedPenaltyGasCost()` line 206

`_actualGasCost / _actualUserOpFeePerGas` will revert if `_actualUserOpFeePerGas == 0`. While the EntryPoint should never pass 0, there's no defensive check. If this reverts, the entire postOp fails, which could have implications for stuck user funds depending on EntryPoint behavior.

**Verification approach:** Write a rule showing that `_expectedPenaltyGasCost` reverts when `_actualUserOpFeePerGas == 0`.

### FINDING-6: Signer keys rejected in validateSignature but accepted in validatePaymasterUserOp
**Severity: INFORMATIONAL**
**Location:** `Validations.sol:_validateWebAuthnSigner()` line 366, `_validateSecp256k1Signer()` line 393

In both functions, `if (key._isSigner()) return SIG_VALIDATION_FAILED;` — signer-role keys are explicitly rejected for account-level validation. But in `_validateVerifyingMode()` (line 110), the condition `key._keyValidation() || key._isSigner()` ACCEPTS signer keys for paymaster sponsorship.

This asymmetry is likely intentional (different trust levels for account ops vs paymaster sponsorship) but should be explicitly documented and verified.

### FINDING-7: P256 key type constraint for SuperAdmin
**Severity: INFORMATIONAL**
**Location:** `KeyLib.sol:_isSuperAdmin()` line 45

`uint8(_k.keyType) < uint8(1)` means P256 (value 0) keys CANNOT be SuperAdmin. Only WebAuthnP256 (1) and Secp256k1 (2) are valid for SuperAdmin role. Similarly for Admin (`_isAdmin()` line 55). This means P256 is only valid for Signer-role keys.

---

## Spec File Structure (recommended)

```
certora/Paymaster/
  PaymasterHarness.sol          -- harness contract exposing internals
  PaymasterEntry.conf           -- prover configuration
  PaymasterEntry.spec           -- main spec file
  access_control.spec           -- AC-1 through AC-11
  key_management.spec           -- KM-1 through KM-6
  funds_flow.spec               -- FF-1 through FF-8
  signature_validation.spec     -- SV-1 through SV-7
  parsing.spec                  -- PE-1 through PE-9 (pure function rules)
```

Split specs are recommended because:
- Each spec runs independently (parallel prover runs)
- Easier to debug timeouts (isolated rule sets)
- Ghost+hook definitions don't interfere across concerns

---

## Ghost + Hook + Invariant Designs

### Design 1: Key Count Tracking

```cvl
ghost mathint ghostKeyCount {
    init_state axiom ghostKeyCount == 0;
}

// Hook on keyHashes set additions
// Note: EnumerableSetLib storage layout must be reverse-engineered for exact slot

invariant keyCountConsistency()
    to_mathint(keyCount()) == ghostKeyCount;
```

### Design 2: Key Existence Consistency

```cvl
ghost mapping(bytes32 => bool) ghostKeyExists {
    init_state axiom forall bytes32 h. !ghostKeyExists[h];
}

// Hooks on keyStorage writes
// When keyStorage[h] goes from length 0 to >0: ghostKeyExists[h] = true
// When keyStorage[h] goes from length >0 to 0: ghostKeyExists[h] = false
```

### Design 3: SuperAdmin Count (for FINDING-1)

```cvl
ghost mathint superAdminCount {
    init_state axiom superAdminCount == 0;
}

// Hook on keyStorage writes — when a SuperAdmin key is added, increment
// When a SuperAdmin key is removed, decrement

invariant atLeastOneSuperAdmin()
    superAdminCount >= 1;
// This invariant is expected to FAIL, confirming FINDING-1
```

---

## Recommended Verification Order

1. **Start with pure function rules** (PE-7, PE-8, PE-9) — _getCostInToken, _expectedPenaltyGasCost. These are standalone, no harness needed, fast feedback.

2. **Access control rules** (AC-1 through AC-4) — _requireFromEntryPoint checks. Need a harness but logic is simple.

3. **Key management parametric rules** (AC-5, AC-6, AC-8, AC-9, AC-10) — role-based restrictions on key operations.

4. **Signature validation rules** (SV-4, SV-5, SV-6) — signer type handling correctness.

5. **Ghost+hook invariants** (KM-1, KM-3) — key storage consistency. Most complex, tackle last.

6. **Funds flow rules** (FF-4, FF-6) — token transfer correctness in ERC20 mode.

---

## Deep Analysis Round 2: Cross-Function Flows and Attack Vectors

### Flow 1: The executeBatch -> Arbitrary Call Escalation Chain

**Attack surface:** `executeBatch` is gated by `_requireFromEntryPoint()`, but once past that gate, it executes ANY calls via `Exec.call()`. The only restriction is what the EntryPoint allows.

**Cross-function concern:** `executeBatch` can call back into the Paymaster itself (`address(this)`). The `onlySuperAdminOrAdminKeyOrEp` modifier allows `msg.sender == address(this)`, which means:

```
EntryPoint -> executeBatch -> call(address(this), 0, withdrawTo.selector + args)
```

This is intentional (the paymaster needs to call itself through the EntryPoint), but it means **any operation gated by `onlySuperAdminOrAdminKeyOrEp` or `onlySuperAdminKeyOrEp` is effectively callable through executeBatch** — since `msg.sender == address(this)` passes both modifiers.

**FV Property (FLOW-1):**
```
If executeBatch calls address(this) with selector X:
  The effective access control for X is just _requireFromEntryPoint()
  NOT the modifier's SuperAdmin/Admin checks
```

**Implication:** Any userOp validated by the EntryPoint (even with just an Admin or Signer key) can trigger executeBatch, which can then call `withdrawTo`, `withdrawStake`, `revoke`, or any other self-function. The Admin-level calldata validation (`_validateCallData`) is the ONLY defense.

### Flow 2: The _validateCallData Bypass (Deeper Analysis of FINDING-3)

Looking more carefully at `_validateCalls`:

```solidity
for (uint256 i = 0; i < arrLength;) {
    bytes calldata calls = LibBytes.dynamicStructInCalldata(arrData, i * 0x20);
    bytes calldata data = LibBytes.bytesInCalldata(calls, 0x40);

    if (data.length >= 4) {
        bytes4 sel = bytes4(LibBytes.loadCalldata(data, 0x00));
        if (sel == Types.APPROVE_SEL) {
            return address(uint160(uint256(LibBytes.loadCalldata(data, 0x04)))) == address(this);
        } else {
            return sel._isAllowedSelector();
        }
    }
    unchecked { ++i; }
}
return true;
```

**Multi-step attack vector:**
1. First call: `data.length < 4` (falls through, no return)
2. Second call: `data.length < 4` (falls through again)
3. ... all calls have data.length < 4
4. Loop ends, `return true`

This means **a batch of calls where ALL calls have data shorter than 4 bytes bypasses ALL selector checks**. ETH transfers (value transfers with no data) pass through completely unvalidated.

**FV Property (FLOW-2a):**
```
_validateCalls returns true for ANY batch where all calls have data.length < 4
regardless of targets or values
```

**FV Property (FLOW-2b):**
```
A batch of [allowed_call, arbitrary_call, arbitrary_call] passes validation
because the first allowed_call causes an immediate return true
```

**Combined impact with FLOW-1:** An Admin key can:
1. Submit a userOp with calldata = `executeBatch([{target: X, value: Y, data: ""}])`
2. `_validateCallData` sees executeBatch selector -> calls `_validateCalls`
3. `_validateCalls` finds data.length == 0 < 4 for all calls
4. Returns `true`
5. executeBatch sends ETH to arbitrary address X

**FINDING-8: Admin keys can drain ETH via executeBatch with value transfers**
**Severity: HIGH**
**Location:** `Validations.sol:_validateCalls()` lines 425-433

### Flow 3: The validateUserOp vs validatePaymasterUserOp Duality

The contract has TWO validation entry points from the EntryPoint:

1. `validateUserOp` (BasePaymaster.sol:11) — validates the account's own userOp signature
2. `validatePaymasterUserOp` (Validations.sol:30) — validates as a third-party paymaster

These use DIFFERENT validation logic:
- `validateUserOp` -> `_validateSignature` -> rejects Signer keys, checks calldata for Admin
- `validatePaymasterUserOp` -> `_validateVerifyingMode`/`_validateERC20Mode` -> accepts Signer keys (verifying), no calldata check

**FV Property (FLOW-3):**
```
For the same key K and same userOp:
  validateUserOp may return FAILED while validatePaymasterUserOp returns SUCCESS
  (because validatePaymasterUserOp doesn't check calldata for non-ERC20 modes)
```

This is architecturally intentional but creates a subtle risk: the same key has different power depending on whether the contract is acting as an account vs a paymaster.

### Flow 4: The Hash Domain Separation Issue

The `Paymaster.sol` override of `getHash` adds EIP-7702 support:

```solidity
function getHash(...) public view override returns (bytes32) {
    bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(_userOp);
    bytes32 originalHash = super.getHash(_mode, _userOp, _signerType);
    return keccak256(abi.encode(originalHash, overrideInitCodeHash));
}
```

When `overrideInitCodeHash == 0` (non-EIP-7702), the hash becomes `keccak256(abi.encode(originalHash, 0))`. This is DIFFERENT from `originalHash` itself.

**FV Property (FLOW-4):**
```
The hash computed in Paymaster.getHash is NEVER equal to the hash in Validations.getHash
because the outer keccak256(abi.encode(originalHash, overrideInitCodeHash)) always wraps it
```

This means signatures are always computed against the Paymaster-level hash, never the base Validations-level hash. Domain separation is correct, but verify that no code path accidentally uses the base hash.

### Flow 5: The Signer Key Expiry Timing Attack

`_keyValidation` checks `key.expiry < uint40(block.timestamp)`. The Signer key's `_isSigner()` check does NOT verify expiry — it only checks structural fields (isSuperAdmin, isAdmin, expiry != max, publicKey.length).

In `_validateVerifyingMode` line 110:
```solidity
if (key._keyValidation() || key._isSigner()) {
```

This means:
- If `_keyValidation()` is true (not expired): proceeds to verify signature
- If `_keyValidation()` is false BUT `_isSigner()` is true: STILL proceeds to verify signature

**FINDING-9: Expired Signer keys can still authorize paymaster operations in verifying mode**
**Severity: HIGH**
**Location:** `Validations.sol:_validateVerifyingMode()` lines 110, 117, 123

An expired Signer key (expiry < block.timestamp) fails `_keyValidation()` but passes `_isSigner()` (because `_isSigner` doesn't check expiry). The `||` means the expired key still enters the signature verification block. If the signature is cryptographically valid, `isSignatureValid = true`, and the validation passes.

**Verification approach:** Write a rule:
```
For a key where expiry < block.timestamp AND key is a Signer role:
  _validateVerifyingMode should return sigFailed == true
  (This is expected to FAIL, confirming the bug)
```

**This does NOT affect ERC20 mode** because ERC20 mode uses `key._keyValidation()` only (no `|| key._isSigner()`).

### Flow 6: The _postOp Double-Charge Scenario

In `_postOp`, two token transfers can happen:

1. **Settlement transfer** (lines 242-247): sender <-> treasury based on costInToken vs preFundCharged
2. **Recipient surplus** (lines 251-253): sender -> recipient if preFundInToken > costInToken

The `preFundInToken` for the recipient check is recalculated as `(ctx.preFund * ctx.exchangeRate) / 1e18`, which is the ETH-denominated preFund converted to tokens. This is DIFFERENT from `ctx.preFundCharged` (which is the actual token amount charged during validatePaymasterUserOp).

**FV Property (FLOW-6a):**
```
The total tokens transferred FROM sender in postOp =
  max(0, costInToken - preFundCharged) + max(0, preFundInToken - costInToken)
```

**Edge case:** If `preFundCharged > costInToken` (refund direction) but also `preFundInToken > costInToken`, the sender gets a refund via settlement BUT also pays the surplus to recipient. These could partially cancel out but the sender still pays the recipient.

**FV Property (FLOW-6b):**
```
If preFundCharged > costInToken AND preFundInToken > costInToken:
  sender receives (preFundCharged - costInToken) from treasury
  sender pays (preFundInToken - costInToken) to recipient
  Net = received - paid = preFundCharged - preFundInToken
  If preFundInToken > preFundCharged: sender LOSES tokens in the refund case
```

**FINDING-10: Possible net loss for user in postOp refund + recipient scenario**
**Severity: MEDIUM**
**Location:** `Validations.sol:_postOp()` lines 239-253

When the settlement is a refund (costInToken < preFundCharged) but there's also a recipient surplus distribution, the user may end up paying more than the actual gas cost. The recipient payment is based on `preFundInToken` (recalculated from ETH preFund), not `preFundCharged` (actual token pre-charge).

### Flow 7: The self-call Access Control Weakening

Both modifiers allow `msg.sender == address(this)`:

```solidity
modifier onlySuperAdminOrAdminKeyOrEp() {
    ... && msg.sender != address(entryPoint) && msg.sender != address(this)
```

```solidity
modifier onlySuperAdminKeyOrEp() {
    ... && msg.sender != address(entryPoint) && msg.sender != address(this)
```

Combined with `executeBatch`, this creates a privilege escalation path:

```
EntryPoint -> executeBatch -> [
    call(this, 0, addSigner(malicious_key)),     // passes: msg.sender == this
    call(this, 0, withdrawTo(attacker, balance))  // passes: msg.sender == this
]
```

But `_validateCallData` should block this... except for FINDING-3 (only first call checked) and FINDING-8 (calls with data < 4 bytes bypass).

**FV Property (FLOW-7):**
```
Parametric: For any function f with onlySuperAdminKeyOrEp modifier:
  If executeBatch is called with a Call targeting address(this) with f's selector:
  f executes regardless of the original userOp signer's role
```

**FINDING-11: executeBatch + self-call bypasses role-specific access control**
**Severity: HIGH (dependent on FINDING-3)**
**Location:** `ManagerAccessControl.sol` modifiers + `BasePaymaster.sol:executeBatch`

If FINDING-3 is exploitable (and it appears to be), then an Admin-signed userOp can:
1. executeBatch with first call = allowed selector, second call = `revoke(superAdminKeyHash)`
2. First call passes `_validateCalls`, function returns true
3. Second call executes via `Exec.call` to `address(this)` with `revoke` selector
4. `msg.sender == address(this)` passes `onlySuperAdminKeyOrEp`
5. SuperAdmin key is revoked by an Admin

### Flow 8: The P256 validateSignature Dead Path

In `_validateSignature` (Validations.sol:341):
```solidity
if (signerType == uint8(SignerType.P256)) {
    validationData = SIG_VALIDATION_FAILED;
}
```

P256 signer type in `_validateSignature` ALWAYS returns FAILED. No signature verification is even attempted. This is a dead code path — P256 keys can never pass account-level validation via `validateUserOp`.

However, P256 keys CAN pass paymaster validation via `_validateVerifyingMode` (line 107-113) and `_validateERC20Mode` (line 152-158), where full P256 verification occurs.

**FV Property (FLOW-8):**
```
For signerType == P256:
  _validateSignature ALWAYS returns SIG_VALIDATION_FAILED
  regardless of the signature content or key validity
```

**FINDING-12: P256 account-level validation is intentionally dead**
**Severity: INFORMATIONAL**
**Location:** `Validations.sol:_validateSignature()` line 341-343

P256 can only be used for paymaster-mode sponsorship, never for account-level userOp validation. This should be documented clearly.

### Flow 9: The getHash Mode-Dependent Exclusion Length

In `Validations.getHash` (line 260-300), for ERC20 mode, the hash excludes the signature portion by computing a dynamic `paymasterDataLength` based on optional fields. But this length calculation reads from `_userOp.paymasterAndData` at a specific offset to check `combinedByte` flags.

**Subtle issue:** The `combinedByte` read at line 278 is at offset `PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH`. This is the FIRST byte of the ERC20 config (the flags byte). But `_parsePaymasterAndData` reads the mode/allowAllBundlers from offset `PAYMASTER_DATA_OFFSET`. So:
- Byte at `PAYMASTER_DATA_OFFSET`: mode (7 bits) + allowAllBundlers (1 bit)
- Byte at `PAYMASTER_DATA_OFFSET + 1`: constantFeePresent + recipientPresent + preFundPresent (config flags)

The hash function reads the config flags byte to determine exclusion length. If the flags byte is manipulated (by changing which optional fields are present), the hash changes, which means the signature is over a different hash.

**FV Property (FLOW-9):**
```
For two userOps that are identical except for the config flags byte:
  getHash returns different values
  (this is correct behavior — the hash includes the flags)
```

This is actually correct, but important to verify — the hash must cover the config flags to prevent a malleability attack where optional fields are added/removed post-signature.

### Flow 10: The _payPrefund Ignoring Failure

In `BasePaymaster._payPrefund` (line 55-61):
```solidity
(bool success,) = payable(msg.sender).call{ value: missingAccountFunds }("");
(success);  // Deliberately ignoring failure
```

The `(success);` is a no-op — it references the variable to suppress the unused warning but doesn't check it. The comment says "Ignore failure (its EntryPoint's job to verify, not account.)"

**FV Property (FLOW-10):**
```
_payPrefund never reverts regardless of whether the ETH transfer succeeds or fails
(unless the contract has insufficient ETH, in which case the low-level call returns false)
```

Actually, `address.call{value: X}` will revert if the contract doesn't have enough ETH. Wait — no, it returns `false`. So `_payPrefund` truly never reverts, even if the paymaster has no ETH. The EntryPoint will detect the missing deposit and revert the outer transaction.

**FINDING-13: _payPrefund silently fails if contract has insufficient ETH**
**Severity: LOW**
**Location:** `BasePaymaster.sol:_payPrefund()` lines 56-58

This is by design (the comment explains), but formal verification should confirm that the EntryPoint's deposit check provides the safety net. If for any reason the EntryPoint doesn't verify the deposit, funds are not transferred.

---

## Updated Findings Summary (Round 1 + Round 2)

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| F-1 | No protection against removing last SuperAdmin | HIGH | Key Management |
| F-2 | Constructor doesn't check for duplicate keys | MEDIUM | Key Management |
| F-3 | _validateCalls only checks FIRST call in batch | HIGH | Access Control |
| F-4 | postOp zero-cost transfer when costInToken == preFundCharged | LOW | Gas Optimization |
| F-5 | Division by zero in _expectedPenaltyGasCost | MEDIUM | Arithmetic |
| F-6 | Signer vs Admin/SuperAdmin role asymmetry across validation paths | INFO | Architecture |
| F-7 | P256 keys cannot be SuperAdmin or Admin | INFO | Architecture |
| F-8 | Admin keys can drain ETH via executeBatch with data-less calls | HIGH | Access Control |
| F-9 | Expired Signer keys still authorize verifying mode operations | HIGH | Signature Validation |
| F-10 | Net token loss for user in postOp refund + recipient scenario | MEDIUM | Funds Flow |
| F-11 | executeBatch + self-call bypasses role-specific access control | HIGH | Access Control |
| F-12 | P256 account-level validation is intentionally dead code | INFO | Architecture |
| F-13 | _payPrefund silently fails with insufficient ETH | LOW | Funds Flow |

### Critical Attack Chain: F-3 + F-11

The most severe combination: FINDING-3 enables FINDING-11.

```
1. Admin key signs userOp
2. callData = executeBatch([ {target:this, value:0, data:deposit()}, {target:this, value:0, data:revoke(superAdminHash)} ])
3. _validateCallData -> _validateCalls
4. First call: selector = deposit() -> _isAllowedSelector -> true -> RETURN TRUE
5. Second call is NEVER checked
6. executeBatch executes both calls
7. deposit() executes (harmless)
8. revoke(superAdminHash) executes with msg.sender == address(this) -> passes modifier
9. SuperAdmin key is revoked by Admin
```

**FV approach:** This is the highest-priority verification target. Write a parametric rule proving that after any execution, a SuperAdmin key that existed before still exists. If this fails when the caller is an Admin, it confirms the attack chain.

---

## New Verification Properties from Round 2

| ID | Property | Priority |
|----|----------|----------|
| FLOW-1 | executeBatch self-calls bypass modifier role checks | Tier 1 |
| FLOW-2a | Batch calls with data < 4 bytes bypass all selector validation | Tier 1 |
| FLOW-2b | Only first call with data >= 4 bytes is validated in batch | Tier 1 |
| FLOW-3 | Same key can pass paymaster validation but fail account validation | Tier 2 |
| FLOW-5 / F-9 | Expired Signer keys pass verifying mode (the `||` bug) | Tier 1 |
| FLOW-6a | Total tokens transferred from sender in postOp | Tier 2 |
| FLOW-6b | Net user loss in refund + recipient scenario | Tier 2 |
| FLOW-7 | executeBatch + self-call privilege escalation for Admin | Tier 1 |
| FLOW-8 | P256 always returns FAILED in validateSignature | Tier 3 |
| FLOW-10 | _payPrefund never reverts | Tier 3 |

## Updated Verification Priority

### Tier 0: VERIFY IMMEDIATELY (attack chains)
1. **F-3 + F-11:** _validateCalls bypass + self-call privilege escalation
2. **F-9:** Expired Signer key bypass in verifying mode
3. **F-8:** ETH drain via data-less batch calls
4. **F-1:** Last SuperAdmin removal

### Tier 1: MUST VERIFY (access control)
5. AC-1 through AC-4 (EntryPoint gates)
6. AC-5 through AC-8 (role-based gates)
7. FLOW-1 (self-call escalation pattern)

### Tier 2: SHOULD VERIFY (funds + consistency)
8. FF-6 + FLOW-6 (postOp settlement correctness)
9. PE-7, PE-8, PE-9 (arithmetic correctness)
10. KM-1 through KM-6 (key management invariants)

### Tier 3: NICE TO VERIFY
11. FLOW-8 (P256 dead path)
12. FLOW-10 (_payPrefund behavior)
13. NSE-1 through NSE-3 (no side effects)
