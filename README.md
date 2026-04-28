# paymaster-multi-signer

ERC-4337 paymaster with a hierarchical multi-key authorization model, three signature schemes, two operating modes, and EIP-7702 delegation support.

## Overview

`PaymasterEntry` is a single contract bound at deployment to one ERC-4337 EntryPoint and one WebAuthn verifier. Every privileged action — sponsoring a userOp, depositing, withdrawing, adding signers, executing admin batches — is gated by a `Key` registered onchain in one of three roles:

- **superAdmin** — never expires, can do everything (rotate keys, withdraw, sponsor).
- **admin** — finite expiry, can sponsor and call a fixed selector whitelist (`deposit`, `addStake`, `unlockStake`, `addSigner`, plus `approve(paymaster, x)` inside `executeBatch`).
- **signer** — finite expiry, may **only** sign paymaster sponsorships.

Sponsorships run in one of two modes selected per-userOp via the `mode` byte in `paymasterAndData`:

- **Verifying mode (`0`)** — pure gas sponsorship; no `postOp`.
- **ERC-20 mode (`1`)** — user pays for gas in an ERC-20 token. Optional pre-fund at validation, settlement in `postOp` with a 10% unused-gas penalty applied per ERC-4337.

Three signer types are accepted: `P256` (NIST secp256r1), `WebAuthnP256` (passkey), and `Secp256k1` (EOA / ECDSA). The signer type is part of the key hash so the same coordinates registered under different types are distinct keys.

For EIP-7702 userOps, `getHash` mixes the EOA's delegation target into the digest, so a signer's authorization is bound to the specific contract the EOA delegates to at validation time.

## Documentation

Full developer documentation lives in [`documentation/`](./documentation/):

| # | Doc | Topic |
|---|-----|-------|
| — | [README](./documentation/README.md) | Doc index and reading order |
| 1 | [01-architecture.md](./documentation/01-architecture.md) | Inheritance graph, layer responsibilities, library deps |
| 2 | [02-keys-and-roles.md](./documentation/02-keys-and-roles.md) | `Key` struct, the three roles, lifecycle, hashing rule |
| 3 | [03-signature-schemes.md](./documentation/03-signature-schemes.md) | P256, WebAuthn, Secp256k1 layouts and verifier dispatch |
| 4 | [04-paymaster-modes.md](./documentation/04-paymaster-modes.md) | Verifying vs ERC-20, validation flow diagrams |
| 5 | [05-paymasterAndData-encoding.md](./documentation/05-paymasterAndData-encoding.md) | Byte-level layout, optional-field bit flags |
| 6 | [06-erc20-settlement.md](./documentation/06-erc20-settlement.md) | Pre-fund, `postOp`, cost conversion, penalty math |
| 7 | [07-eip7702-support.md](./documentation/07-eip7702-support.md) | Delegation detection and hash override |
| 8 | [08-bundler-allowlist.md](./documentation/08-bundler-allowlist.md) | `isBundlerAllowed`, `allowAllBundlers` bit |
| 9 | [09-deployment-and-integration.md](./documentation/09-deployment-and-integration.md) | Deploy params, building `paymasterAndData`, admin path |

Suggested reading order:

- **Integrators**: 01 → 02 → 04 → 05 → 09.
- **Auditors**: 01 → 02 → 03 → 04 → 06 → 07 → 08, then [`INVARIANTS.md`](./INVARIANTS.md).

## Source layout

```
contracts/
  core/        Paymaster logic (entry, validations, key/signer management, storage, access)
  interface/   External-facing interfaces for each core module
  library/     Pure helpers: KeyLib, PaymasterLib, Eip7702Support, WebAuthn, P256
  type/        Types.sol, Errors.sol, Events.sol
  utils/       WebAuthnVerifier (deployed separately, bound at construction)
```

The deployed contract is `contracts/core/PaymasterEntry.sol`; everything above it in the inheritance chain is `abstract`. See [`documentation/01-architecture.md`](./documentation/01-architecture.md) for the inheritance graph.

## Toolchain

- Solidity `0.8.34`, `evm_version = "prague"` (see [`foundry.toml`](./foundry.toml)).
- Foundry. Common commands:
  - `forge build` — compile.
  - `forge test` — run the test suite under [`test/`](./test/).
  - `forge fmt` — format (config in `[fmt]` of `foundry.toml`).
- External libs: `@solady/src` (P256, WebAuthn, EnumerableSet, LibBytes, SafeTransferLib), `@account-abstraction/contracts` (EntryPoint v0.9), `@openzeppelin/contracts` (ECDSA, MessageHashUtils).

## Invariants

The contract enforces 20+ invariants over keys, storage, modes, and authorization. The full list is in [`INVARIANTS.md`](./INVARIANTS.md).

## License

MIT.
