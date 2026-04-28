# 08 — Bundler Allowlist

The paymaster can restrict which bundlers may submit userOps that consume its sponsorship. This is a coarse policy switch that runs before any signature work in `validatePaymasterUserOp`.

## Storage and lifecycle

- `mapping(address => bool) public isBundlerAllowed` lives in `core/Storage.sol`.
- It is **populated only in the `PaymasterEntry` constructor**:

```solidity
for (i = 0; i < _allowedBundlers.length;) {
    if (_allowedBundlers[i] == address(0)) revert();
    isBundlerAllowed[_allowedBundlers[i]] = true;
    unchecked { ++i; }
}
```

- There is no setter on the paymaster — `isBundlerAllowed` is effectively **write-once at deployment**. The only way to change the allowlist post-deployment is via `executeBatch` calling into a future setter, but no such setter is exposed today.

## Per-userOp behavior

`Validations._validatePaymasterUserOp` checks the allowlist against `tx.origin`:

```solidity
(uint8 mode, bool allowAllBundlers, bytes calldata cfg) =
    userOp.paymasterAndData._parsePaymasterAndData(PAYMASTER_DATA_OFFSET);

if (!allowAllBundlers && !isBundlerAllowed[tx.origin]) {
    revert BundlerNotAllowed(tx.origin);
}
```

Two ways a userOp passes the gate:

1. The `allowAllBundlers` bit is set in the mode byte → no allowlist check at all.
2. The bit is clear → `tx.origin` (the bundler EOA) must be in `isBundlerAllowed`.

## The `allowAllBundlers` bit

Lives in bit 0 of the mode byte at `paymasterAndData[PAYMASTER_DATA_OFFSET]` (see [05-paymasterAndData-encoding.md](./05-paymasterAndData-encoding.md)). The signer chooses per-userOp whether to enforce the allowlist:

| Bit | Meaning |
|-----|---------|
| `0` | Enforce the bundler allowlist for this userOp |
| `1` | Allow any bundler |

Because the bit is part of `paymasterAndData` and `paymasterAndData` is part of the digest signed by the paymaster signer (via `getHash`), the choice is bound to the signer's authorization. A bundler cannot flip the bit on a signed userOp without invalidating the signature.

## Why `tx.origin`

The check is on `tx.origin` rather than `msg.sender` because, in ERC-4337 v0.7+, the EntryPoint is always `msg.sender` when the paymaster runs. `tx.origin` is the bundler EOA that submitted the bundle. This works because validation rules forbid the paymaster from depending on `tx.origin` for *correctness*, but allow it for **opcode-policy gating** — which is exactly what an allowlist is.

## Practical implications

- **Closed paymaster**: deploy with a small set of trusted bundler addresses, sign userOps with `allowAllBundlers = false`. Unauthorized bundlers cannot use the paymaster's deposit.
- **Open paymaster**: sign with `allowAllBundlers = true`; the allowlist is irrelevant. The empty allowlist (no bundlers added at deploy time) is fine in this model.
- **Mixed**: deploy with an allowlist, but emit some sponsorships with `allowAllBundlers = true` (e.g. for public auctions) and others gated.

## Failure mode

When the gate trips: revert with `BundlerNotAllowed(tx.origin)`. This happens **before** signature verification, so it costs the bundler validation gas but leaks no signature material.
