# 01 — Architecture

## Inheritance graph

The deployed contract is `PaymasterEntry`. It inherits a linear stack of abstract contracts, each adding one concern.

```mermaid
classDiagram
    class Storage {
        +entryPoint: IEntryPoint
        +webAuthnVerifier: IWebAuthnVerifier
        +isBundlerAllowed: mapping
        #keyHashes: EnumerableSet
        #keyStorage: mapping
    }
    class ManagerAccessControl {
        <<modifiers>>
        +onlySuperAdminKeyOrEp
        +onlySuperAdminOrAdminKeyOrEp
    }
    class KeysManager {
        +authorizeAdmin(Key)
        +revoke(bytes32)
        +getKey / getKeys / keyAt / keyCount
        #_addKey / _removeKey
    }
    class MultiSigner {
        +addSigner(Key)
        +removeSigner(bytes32)
    }
    class BasePaymaster {
        +validateUserOp
        +deposit / withdrawTo
        +addStake / unlockStake / withdrawStake
        +executeBatch(Call[])
        #_validateSignature (abstract)
    }
    class Validations {
        +validatePaymasterUserOp
        +postOp
        +getHash
        #_validateVerifyingMode
        #_validateERC20Mode
        #_postOp
        #_validateSignature
    }
    class Paymaster {
        +getHash override (EIP-7702)
    }
    class PaymasterEntry {
        +constructor
    }

    Storage <|-- ManagerAccessControl
    ManagerAccessControl <|-- KeysManager
    KeysManager <|-- MultiSigner
    MultiSigner <|-- BasePaymaster
    BasePaymaster <|-- Validations
    Validations <|-- Paymaster
    Paymaster <|-- PaymasterEntry
```

## Per-layer responsibility

| Layer | File | What it owns |
|-------|------|--------------|
| `Storage` | `core/Storage.sol` | Immutable bindings (`entryPoint`, `webAuthnVerifier`), key set + encoded key map, bundler allowlist. |
| `ManagerAccessControl` | `core/ManagerAccessControl.sol` | The two gating modifiers. Treats `msg.sender == entryPoint` and `msg.sender == address(this)` (self-call via `executeBatch`) as authorized. |
| `KeysManager` | `core/KeysManager.sol` | Add admin keys, revoke any key, enumerate keys, read-back the packed key encoding. |
| `MultiSigner` | `core/MultiSigner.sol` | Add/remove signer keys. Removal of admin/superAdmin via `removeSigner` is blocked (`KillSwitch`); only `revoke` can remove them. |
| `BasePaymaster` | `core/BasePaymaster.sol` | EntryPoint-facing surface for the paymaster *as an account*: `validateUserOp`, deposit/stake operations, `executeBatch`. |
| `Validations` | `core/Validations.sol` | EntryPoint-facing surface for the paymaster *as a paymaster*: `validatePaymasterUserOp`, `postOp`, the per-mode validators, `getHash`, and the account-level `_validateSignature` override. |
| `Paymaster` | `core/Paymaster.sol` | Wraps `getHash` to mix in the EIP-7702 delegation override. |
| `PaymasterEntry` | `core/PaymasterEntry.sol` | Constructor: validates initial keys, populates the bundler allowlist, binds EntryPoint and verifier. |

## Library dependencies

```mermaid
classDiagram
    class KeyLib {
        hash(Key / address / qx,qy,type)
        _isSuperAdmin / _isAdmin / _isSigner
        _keyValidation
        _validateSignatureLength
        _unpackP256Signature
        _unpackWebAuthnCoordinats
        _isAllowedSelector
    }
    class PaymasterLib {
        _parsePaymasterAndData
        _parseVerifyingConfig
        _parseErc20Config
        _createPostOpContext
        _parsePostOpContext
        _getCostInToken
    }
    class Eip7702Support {
        _getEip7702InitCodeHashOverride
        _isEip7702InitCode
        _getEip7702Delegate
    }
    class WebAuthnVerifier {
        verifyP256Signature
        verifyEncodedSignature
        verifySignature
        verifyCompactSignature
    }

    Validations ..> KeyLib
    Validations ..> PaymasterLib
    Validations ..> WebAuthnVerifier : webAuthnVerifier (immutable)
    Paymaster ..> Eip7702Support
    KeysManager ..> KeyLib
    MultiSigner ..> KeyLib
    PaymasterLib ..> KeyLib
```

`WebAuthnVerifier` lives in `contracts/utils/` and is deployed as a standalone contract. The paymaster stores its address in the `webAuthnVerifier` immutable.

## Two EntryPoint-facing surfaces

The paymaster is dual-role:

- As an **account** — `validateUserOp` is called when a userOp is sent *from* this contract (e.g. an admin batches `deposit()` through `executeBatch`).
- As a **paymaster** — `validatePaymasterUserOp` / `postOp` are called when this contract appears in another userOp's `paymasterAndData`.

The two flows have separate signature-validation paths in `Validations`:
- `_validateSignature` (account path) — only superAdmin and admin keys may sign; signer keys are rejected. Admin keys are further constrained to a selector whitelist.
- `_validateVerifyingMode` / `_validateERC20Mode` (paymaster path) — only signer keys (and any non-expired key with `_isSigner() == true`) may sign sponsorships.
