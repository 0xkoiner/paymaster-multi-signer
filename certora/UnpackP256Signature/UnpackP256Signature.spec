methods {
    function unpackP256Signature(bytes) external returns (bytes32, bytes32, bytes32, bytes32, bool) envfree;
}

rule neverReverts {
    bytes signature;                                                                           
                                                                                                
    unpackP256Signature@withrevert(signature);                                                 
                                                                                                
    assert !lastReverted, "unpackP256Signature should never revert";                           
}

rule prehashFalseWhenNot129 {
    bytes signature;
    require signature.length != 129, "Non-129 byte signature";

    bytes32 r; bytes32 s; bytes32 qx; bytes32 qy; bool prehash;
    (r, s, qx, qy, prehash) = unpackP256Signature(signature);

    assert prehash == false, "prehash must be false when length != 129";
}

rule prehashCanBeTrueAt129 {
    bytes signature;

    require signature.length == 129, "129-byte signature";

    bytes32 r; bytes32 s; bytes32 qx; bytes32 qy; bool prehash;
    (r, s, qx, qy, prehash) = unpackP256Signature(signature);

    satisfy prehash == true, "prehash can be true for 129-byte signatures";
}

rule deterministic {
    bytes signature;

    bytes32 r1; bytes32 s1; bytes32 qx1; bytes32 qy1; bool pre1;
    (r1, s1, qx1, qy1, pre1) = unpackP256Signature(signature);
    bytes32 r2; bytes32 s2; bytes32 qx2; bytes32 qy2; bool pre2;
    (r2, s2, qx2, qy2, pre2) = unpackP256Signature(signature);

    assert r1 == r2 && s1 == s2 && qx1 == qx2 && qy1 == qy2 && pre1 == pre2,
        "Same input must produce same output";
}

rule sanityCheck {
    bytes signature;

    bytes32 r; bytes32 s; bytes32 qx; bytes32 qy; bool prehash;
    (r, s, qx, qy, prehash) = unpackP256Signature(signature);

    satisfy r != to_bytes32(0) && s != to_bytes32(0),
        "Non-zero r and s values exist";
}