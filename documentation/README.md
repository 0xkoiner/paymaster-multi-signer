# paymaster-multi-signer — Developer Documentation

ERC-4337 paymaster with a hierarchical multi-key authorization model, three signature schemes, two operating modes, and EIP-7702 delegation support.

## What this paymaster is

- A **paymaster** bound to a single ERC-4337 EntryPoint and a single WebAuthn verifier (both immutable, set at construction).
- A **multi-key authorization layer**: every privileged action — sponsoring a userOp, depositing, withdrawing, adding signers, executing admin batches — is gated by a `Key` registered onchain in one of three roles (`superAdmin` / `admin` / `signer`).
- **Two sponsorship modes** selected per-userOp via the `mode` byte in `paymasterAndData`:
  - `0` — **Verifying mode**: pure gas sponsorship, signed authorization only.
  - `1` — **ERC-20 mode**: user pays in ERC-20 tokens; paymaster pre-funds gas, settles in `postOp`.
- **Three signer types**: `P256` (NIST secp256r1), `WebAuthnP256` (passkey), `Secp256k1` (EOA / ECDSA).
- **EIP-7702 awareness**: `getHash` mixes in the delegation target so signed authorizations are tied to the actual code an EOA delegates to.

## Document index

| # | Doc | Topic |
|---|-----|-------|
| 1 | [01-architecture.md](./01-architecture.md) | Inheritance graph, layer responsibilities |
| 2 | [02-keys-and-roles.md](./02-keys-and-roles.md) | `Key` struct, roles, lifecycle, hashing |
| 3 | [03-signature-schemes.md](./03-signature-schemes.md) | P256, WebAuthn, Secp256k1 verification |
| 4 | [04-paymaster-modes.md](./04-paymaster-modes.md) | Verifying vs ERC-20, validation flows |
| 5 | [05-paymasterAndData-encoding.md](./05-paymasterAndData-encoding.md) | Byte layout for both modes |
| 6 | [06-erc20-settlement.md](./06-erc20-settlement.md) | Pre-fund, postOp, cost conversion, penalty |
| 7 | [07-eip7702-support.md](./07-eip7702-support.md) | Delegation detection, hash override |
| 8 | [08-bundler-allowlist.md](./08-bundler-allowlist.md) | `isBundlerAllowed`, `allowAllBundlers` bit |
| 9 | [09-deployment-and-integration.md](./09-deployment-and-integration.md) | Deploy params, building `paymasterAndData`, admin path |

## Source layout

```
contracts/
  core/        Paymaster logic (entry, validations, key/signer management, storage, access)
  interface/   External-facing interfaces for each core module
  library/     Pure helpers: KeyLib, PaymasterLib, Eip7702Support, WebAuthn, P256
  type/        Types.sol, Errors.sol, Events.sol
  utils/       WebAuthnVerifier (deployed separately, bound at construction)
```

Invariants enforced by the contracts are listed in the repo-root [`INVARIANTS.md`](../INVARIANTS.md).

## Reading order

For a fresh integrator: 01 → 02 → 04 → 05 → 09. For an auditor: 01 → 02 → 03 → 04 → 06 → 07 → 08.
