# 05 — `paymasterAndData` Encoding

`paymasterAndData` is the field in a `PackedUserOperation` that addresses and parameterizes a paymaster. The structure is:

```
┌──────────────────┬─────────────────────────────┬──────────────────────────────┐
│ paymaster addr   │ paymasterValidationGasLimit │ paymaster-specific data      │
│      20 bytes    │       16 bytes              │  ⇣ (parsed by this contract) │
└──────────────────┴─────────────────────────────┴──────────────────────────────┘
                                                  ^
                                                  PAYMASTER_DATA_OFFSET (52)
```

The first 52 bytes are standard ERC-4337 (`paymasterValidationGasLimit` then `paymasterPostOpGasLimit` are encoded by `UserOperationLib`; this paymaster reads from offset 52). Everything from offset 52 onward is what the contract parses.

## Common prefix (1 byte)

The first byte of the paymaster-specific section is the **mode + bundler flag** byte:

```
offset 52 (PAYMASTER_DATA_OFFSET)
┌──────────┐
│ MMMMMMMA │   M = mode, A = allowAllBundlers
└──────────┘
```

Parsed by `PaymasterLib._parsePaymasterAndData`. The remaining bytes are the **paymaster config**, mode-specific.

## Verifying mode config (13+ bytes)

`PaymasterLib._parseVerifyingConfig`:

```
offset 53 (within paymasterAndData)
┌──────────────┬──────────────┬────────────┬────────────────────┐
│ validUntil   │ validAfter   │ signerType │ signature          │
│   6 bytes    │   6 bytes    │  1 byte    │ var (see schemes)  │
└──────────────┴──────────────┴────────────┴────────────────────┘
   53            59             65          66 .. end
```

Total fixed bytes: `1 + 12 + 1 = 14` plus the signature. Length must be ≥ 12 + signature length, else `PaymasterConfigLengthInvalid`. `signerType > 2` reverts with `IncorrectSignerType`.

## ERC-20 mode config (118+ bytes)

`PaymasterLib._parseErc20Config`. The first byte is a **flag byte** for optional fields:

```
offset 53 (flag byte)
┌──────────┐
│ -----FRC │   C = constantFeePresent (bit 0)
└──────────┘   R = recipientPresent   (bit 1)
               F = preFundPresent     (bit 2)
```

Then the **fixed** required fields:

```
offset 54
┌──────────────┬──────────────┬──────────┬──────────┬──────────────┬──────────────────────────────┬──────────┐
│ validUntil   │ validAfter   │ token    │ postOpGas│ exchangeRate │ paymasterValidationGasLimit  │ treasury │
│   6 bytes    │   6 bytes    │ 20 bytes │ 16 bytes │   32 bytes   │            16 bytes          │ 20 bytes │
└──────────────┴──────────────┴──────────┴──────────┴──────────────┴──────────────────────────────┴──────────┘
   54            60             66        86         102            134                            150
```

Then the **optional** fields, in this order, present only if their flag is set:

```
[ if preFundPresent ]
┌──────────────────┐
│ preFundInToken   │ 16 bytes  (uint128)
└──────────────────┘

[ if constantFeePresent ]
┌──────────────┐
│ constantFee  │ 16 bytes  (uint128)
└──────────────┘

[ if recipientPresent ]
┌──────────────┐
│ recipient    │ 20 bytes  (address)
└──────────────┘
```

Then the **trailer**:

```
┌────────────┬────────────────────┐
│ signerType │ signature          │
│  1 byte    │ var (see schemes)  │
└────────────┴────────────────────┘
```

### Total fixed length

The required portion is `1 + 117 = 118` bytes (the constant `ERC20_PAYMASTER_DATA_LENGTH` is `117` and counts every required byte after the flag byte). Each optional field adds its size:

| All flags | Total fixed before signature |
|-----------|------------------------------|
| none | 118 + 1 (signerType) = 119 |
| preFund | + 16 → 135 |
| preFund + constantFee | + 32 → 151 |
| preFund + constantFee + recipient | + 52 → 171 |

`getHash` re-derives the same length from the flag byte to slice off the signature when computing the digest the signer signs.

### Validation rules in `_parseErc20Config`

- `token == address(0)` → `TokenAddressInvalid`
- `exchangeRate == 0` → `ExchangeRateInvalid`
- `recipientPresent && recipient == address(0)` → `RecipientInvalid`
- `signerType > SignerType.max` → `IncorrectSignerType`
- Signature length must match the signer type → `PaymasterSignatureLengthInvalid`
- Any optional field's bytes must fit in the remaining buffer → `PaymasterConfigLengthInvalid`

## How the signer builds these bytes

The off-chain signer:

1. Picks the mode and the allowAllBundlers bit, packs them: `combined = (mode << 1) | (allowAll ? 1 : 0)`.
2. Builds the paymaster config buffer for the chosen mode.
3. Calls `paymaster.getHash(mode, userOp, signerType)` (off-chain via `eth_call`) to obtain the digest.
4. Wraps the digest with `toEthSignedMessageHash` (the `\x19Ethereum Signed Message:\n32` prefix) and signs.
5. Appends `signerType ‖ signature` to the config and submits the userOp.

`getHash` reads back the same bytes from `paymasterAndData[:PAYMASTER_DATA_OFFSET + paymasterDataLength]`, which **excludes** `signerType ‖ signature` — so the signature does not sign over itself.

## Cross-reference

- For mode-level flow, see [04-paymaster-modes.md](./04-paymaster-modes.md).
- For signature byte layouts, see [03-signature-schemes.md](./03-signature-schemes.md).
- For the post-execution settlement that uses `postOpGas`, `exchangeRate`, etc., see [06-erc20-settlement.md](./06-erc20-settlement.md).
