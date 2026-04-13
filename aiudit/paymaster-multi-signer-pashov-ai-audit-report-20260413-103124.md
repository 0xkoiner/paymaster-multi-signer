# Security Review — paymaster-multi-signer

---

## Scope

|                                  |                                                        |
| -------------------------------- | ------------------------------------------------------ |
| **Mode**                         | DEEP                                                   |
| **Files reviewed**               | `BasePaymaster.sol` · `KeysManager.sol` · `ManagerAccessControl.sol`<br>`MultiSigner.sol` · `Paymaster.sol` · `PaymasterEntry.sol`<br>`Storage.sol` · `Validations.sol` · `KeyLib.sol`<br>`PaymasterLib.sol` · `Eip7702Support.sol` · `WebAuthn.sol`<br>`WebAuthnVerifier.sol` · `P256.sol` · `P256Verifier.sol`<br>`Base64.sol` · `Types.sol` · `Errors.sol` · `Events.sol`<br>`IManagerAccessControl.sol` · `IPaymaster.sol` · `IWebAuthnVerifier.sol` |
| **Confidence threshold (1-100)** | 80                                                     |

---

## Findings

[95] **1. Expired Signer Keys Bypass Expiry Check in Verifying Mode Paymaster Validation**

`Validations._validateVerifyingMode` · Confidence: 95

**Description**
In `_validateVerifyingMode`, the condition `if (key._keyValidation() || key._isSigner())` uses logical OR, meaning that even when `_keyValidation()` returns false (key expired), the check passes if `_isSigner()` returns true, because `_isSigner()` validates role flags but does not check the key's expiry timestamp — allowing an expired signer key to produce valid paymaster signatures indefinitely until explicitly revoked. ERC20 mode is NOT affected as it uses only `_keyValidation()`.

**Fix**

```diff
- if (key._keyValidation() || key._isSigner()) {
+ if (key._keyValidation()) {
```

---

[85] **2. ERC-20 Paymaster Payment Deferred to postOp Allows Allowance-Revoke Griefing**

`Validations._postOp` · Confidence: 85

**Description**
`_validateERC20Mode` does not lock or transfer the full payment token amount from the user during validation — it only optionally charges `preFundInToken` — so a user can include `token.approve(paymaster, 0)` in their userOp callData to revoke allowance before `postOp` executes, causing `safeTransferFrom` in `_postOp` to revert and draining the paymaster's ETH deposit without the user paying any ERC-20 tokens.

**Fix**

```diff
- if (cfg.preFundInToken > 0) {
-     SafeTransferLib.safeTransferFrom(cfg.token, _userOp.sender, cfg.treasury, cfg.preFundInToken);
- }
+ // Transfer the full estimated cost upfront, not just the optional preFundInToken
+ uint256 costInToken = _requiredPreFund._getCostInToken(0, 0, cfg.exchangeRate);
+ uint256 upfrontCharge = costInToken > cfg.preFundInToken ? costInToken : cfg.preFundInToken;
+ if (upfrontCharge > 0) {
+     SafeTransferLib.safeTransferFrom(cfg.token, _userOp.sender, cfg.treasury, upfrontCharge);
+ }
+ // In postOp, only refund excess rather than charging again
```

---

[80] **3. Batch Call Validation Only Checks First Call, Allowing Admin Privilege Escalation**

`Validations._validateCalls` · Confidence: 80

**Description**
The `_validateCalls` function returns immediately upon evaluating the first call in a batch that has `data.length >= 4`, never iterating to validate subsequent calls; an admin key can construct a batch where the first call uses an allowed selector (e.g., `deposit()`) and subsequent calls contain arbitrary selectors (e.g., `withdrawTo`, `revoke`, or external calls), bypassing the admin's intended call restrictions and escalating to superAdmin-equivalent privileges via the `msg.sender == address(this)` allowance in access control modifiers. Compounds with findings #4 and #5: a rogue admin could configure a malicious token via the unvalidated second batch call, then subsequent users' postOps all fail.

**Fix**

```diff
  for (uint256 i = 0; i < arrLength;) {
      bytes calldata calls = LibBytes.dynamicStructInCalldata(arrData, i * 0x20);
      bytes calldata data = LibBytes.bytesInCalldata(calls, 0x40);

      if (data.length >= 4) {
          bytes4 sel = bytes4(LibBytes.loadCalldata(data, 0x00));

          if (sel == Types.APPROVE_SEL) {
-             return address(uint160(uint256(LibBytes.loadCalldata(data, 0x04)))) == address(this);
-         } else {
-             return sel._isAllowedSelector();
+             if (address(uint160(uint256(LibBytes.loadCalldata(data, 0x04)))) != address(this)) {
+                 return false;
+             }
+         } else if (!sel._isAllowedSelector()) {
+             return false;
          }
      }

      unchecked {
          ++i;
      }
  }

  return true;
```

---

[80] **4. Zero-Amount ERC20 Transfer in postOp Causes DoS on Certain Tokens**

`Validations._postOp` · Confidence: 80

**Description**
When `costInToken == ctx.preFundCharged`, `absoluteCostInToken` is computed as 0 and `SafeTransferLib.safeTransferFrom` is called with a zero amount; tokens that revert on zero-value transfers (e.g., LEND) will cause `postOp` to revert and the EntryPoint to enter a failed postOp loop, permanently bricking ERC20-mode sponsorship for that userOp without reimbursing the paymaster.

**Fix**

```diff
+ if (absoluteCostInToken > 0) {
      SafeTransferLib.safeTransferFrom(
          ctx.token,
          costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
          costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
          absoluteCostInToken
      );
+ }
```

---

[80] **5. Blacklistable Token (e.g., USDC) in postOp Causes Unrecoverable Revert Loop**

`Validations._postOp` · Confidence: 80

**Description**
The push-model `safeTransferFrom(token, sender, treasury, amount)` in `_postOp` will revert if the ERC20 token blacklists the sender or treasury after validation but before execution, causing the EntryPoint to re-invoke `postOp` with `PostOpMode.postOpReverted` — which calls the same failing transfer again — permanently bricking that operation and wasting paymaster ETH deposits without token reimbursement.

**Fix**

```diff
- SafeTransferLib.safeTransferFrom(
-     ctx.token,
-     costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
-     costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
-     absoluteCostInToken
- );
+ if (absoluteCostInToken > 0) {
+     (bool ok,) = ctx.token.call(
+         abi.encodeCall(
+             IERC20.transferFrom,
+             (
+                 costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
+                 costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
+                 absoluteCostInToken
+             )
+         )
+     );
+     if (!ok) emit TransferFailed(ctx.sender, ctx.token, absoluteCostInToken);
+ }
```

---

[80] **6. Banned Opcode `TIMESTAMP` Used Inside Paymaster Validation Phase**

`Validations._validateVerifyingMode` / `Validations._validateERC20Mode` · Confidence: 80

**Description**
`_keyValidation()` compares `key.expiry` against `block.timestamp` (a banned opcode per ERC-7562) and is called from both `validatePaymasterUserOp` and `validateUserOp`, causing simulation-execution divergence when a key's expiry crosses the block boundary between simulation and inclusion — bundlers will simulate success but execution will fail (or vice versa), causing unpredictable operation rejections or incorrect sponsorships.

**Fix**

```diff
- function _keyValidation(Key memory _k) internal view returns (bool) {
-     if (_k.expiry < uint40(block.timestamp)) {
-         return false;
-     }
-     return true;
- }
+ // Move time-based validation out of the validation phase.
+ // Encode key.expiry as validUntil in the _packValidationData return value
+ // so EntryPoint enforces the time window without a banned opcode.
```

---

| # | Confidence | Title |
|---|---|---|
| 1 | [95] | Expired Signer Keys Bypass Expiry Check in Verifying Mode |
| 2 | [85] | ERC-20 Paymaster Payment Deferred to postOp Allows Allowance-Revoke Griefing |
| 3 | [80] | Batch Call Validation Only Checks First Call, Allowing Admin Privilege Escalation |
| 4 | [80] | Zero-Amount ERC20 Transfer in postOp Causes DoS on Certain Tokens |
| 5 | [80] | Blacklistable Token in postOp Causes Unrecoverable Revert Loop |
| 6 | [80] | Banned Opcode `TIMESTAMP` Used Inside Paymaster Validation Phase |
| | | **Below Confidence Threshold** |
| 7 | [75] | Fee-on-Transfer Token Accounting Mismatch in ERC20 Paymaster |
| 8 | [75] | ERC20 `_postOp` Double-Charges Sender via Mismatched `preFundInToken` Accounting |
| 9 | [75] | SuperAdmin Can Revoke Own Key, Permanently Locking Contract |
| 10 | [55] | Solady SafeTransferLib Skips Token Contract Existence Check |

---

## Below Confidence Threshold

[75] **7. Fee-on-Transfer Token Accounting Mismatch in ERC20 Paymaster**

`Validations._validateERC20Mode` / `Validations._postOp` · Confidence: 75

**Description**
When a fee-on-transfer ERC20 token is used, the `preFundInToken` transferred in `_validateERC20Mode` credits `treasury` with the nominal amount but the treasury only receives `amount - fee`; `_postOp` then settles using the nominal `preFundCharged` value causing the treasury to attempt refunding amounts it does not hold, potentially reverting the postOp or double-charging the user.

---

[75] **8. ERC20 `_postOp` Double-Charges Sender via Mismatched `preFundInToken` Accounting**

`Validations._postOp` · Confidence: 75

**Description**
In `_postOp`, the second `safeTransferFrom` transfers `preFundInToken - costInToken` from the user to `recipient`, where `preFundInToken` is computed from the ETH-denominated `preFund` field (`ctx.preFund * ctx.exchangeRate / 1e18`) — not from `ctx.preFundCharged` (the token amount actually collected during validation); when a non-zero recipient is set and the ETH-based preFund value exceeds the actual gas cost in tokens, the user is charged a second time beyond what was validated.

---

[75] **9. SuperAdmin Can Revoke Own Key, Permanently Locking Contract Funds and Administration**

`KeysManager.revoke` · Confidence: 75

**Description**
The `revoke` function protected by `onlySuperAdminKeyOrEp` has no check preventing the last superAdmin from revoking their own key; once the sole superAdmin key is removed, no account can pass signature validation for privileged operations (`withdrawTo`, `withdrawStake`, `authorizeAdmin`, `revoke`), permanently locking all EntryPoint deposits and staked ETH with no recovery path.

---

[55] **10. Solady SafeTransferLib Skips Token Contract Existence Check**

`Validations._validateERC20Mode` / `Validations._postOp` · Confidence: 55

**Description**
`SafeTransferLib.safeTransferFrom` from Solady does not verify `token.code.length > 0`, so a userOp referencing a not-yet-deployed token address (e.g., a future CREATE2 address) will have its `transferFrom` silently succeed, allowing the paymaster to sponsor gas without receiving any token payment.

---

> This review was performed by an AI assistant. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Team security reviews, bug bounty programs, and on-chain monitoring are strongly recommended. For a consultation regarding your projects' security, visit [https://www.pashov.com](https://www.pashov.com)
