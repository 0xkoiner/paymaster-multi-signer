methods {
    function validateSignatureLength(bytes, uint8) external envfree;
}

rule p256LengthValidationLastReverted {
    bytes signature;
    uint8 signerType;

    require signerType == 0, "Isolating P256 signer type for this rule";

    validateSignatureLength@withrevert(signature, signerType);

    assert lastReverted <=> (signature.length != 128 && signature.length != 129);
}

rule p256LengthValidationSatisfy {
    bytes signature;
    uint8 signerType;

    require signerType == 0, "Isolating P256 signer type for this rule";

    validateSignatureLength@withrevert(signature, signerType);

    satisfy !lastReverted;
}

rule webAuthnLengthValidationLastReverted {
    bytes signature;
    uint8 signerType;

    require signerType == 1, "Isolating WebAuthn signer type for this rule";
    require signature.length < 352, "Isolating WebAuthn length for this rule";

    validateSignatureLength@withrevert(signature, signerType);

    assert lastReverted, "WebAuthn signatures below 0x160 must revert";
}

rule webauthnMinLengthCanPass {
    bytes signature;
    uint8 signerType;

    require signerType == 1, "Isolating WebAuthn signer type";
    require signature.length == 352, "Exact minimum WebAuthn length";

    validateSignatureLength@withrevert(signature, signerType);

    satisfy !lastReverted, "A 352-byte WebAuthn signature can be valid";
}

rule webauthnSanity {
    bytes signature;
    uint8 signerType;

    require signerType == 1, "Isolating WebAuthn signer type";

    validateSignatureLength@withrevert(signature, signerType);

    satisfy !lastReverted, "At least one valid WebAuthn signature exists";
}

rule webauthnPassImpliesMinLength {
    bytes signature;
    uint8 signerType;

    require signerType == 1, "Isolating WebAuthn signer type";

    validateSignatureLength@withrevert(signature, signerType);

    assert !lastReverted => signature.length >= 352,
        "Accepted WebAuthn signatures must be at least 0x160 bytes";
}

rule webauthnLongCanStillRevert {
    bytes signature;
    uint8 signerType;

    require signerType == 1, "Isolating WebAuthn signer type";
    require signature.length > 352, "Above minimum length";

    validateSignatureLength@withrevert(signature, signerType);

    satisfy lastReverted, "Long WebAuthn signatures can still be invalid";
}

rule secp256k1LengthValidationLastReverted {
    bytes signature;
    uint8 signerType;

    require signerType == 2, "Isolating Secp256k1 signer type for this rule";

    validateSignatureLength@withrevert(signature, signerType);

    assert lastReverted <=> (signature.length != 64 && signature.length != 65);
}

rule secp256k1LengthValidationSatisfy {
    bytes signature;
    uint8 signerType;

    require signerType == 2, "Isolating Secp256k1 signer type for this rule";

    validateSignatureLength@withrevert(signature, signerType);

    satisfy !lastReverted;
}

rule unknownSignerNeverReverts {
    bytes signature;
    uint8 signerType;

    require signerType > 2, "Isolating Unknown signer type for this rule";

    validateSignatureLength@withrevert(signature, signerType);

    assert !lastReverted;
}
