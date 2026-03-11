// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../../data/Constants.sol";
import { Helpers } from "../../helpers/Helpers.t.sol";
import { KeyLib } from "../../../contracts/library/KeyLib.sol";
import { EfficientHashLib } from "@solady/src/utils/EfficientHashLib.sol";

contract TestP256Signature is Helpers {
    using KeyLib for *;

    bytes32 hash = keccak256("hash");

    function setUp() public override {
        super.setUp();
        _ethc();
    }

    function test_p256_signature_extractable() external {
        (bytes memory signature) = _signHashWithP256(hash, false);
        (bytes32 r, bytes32 s, bytes32 qx, bytes32 qy, bool prehash) = signature._unpackP256Signature();
        bool isValid = webAuthnVerifier.verifyP256Signature(hash, r, s, qx, qy);

        assertFalse(prehash, "Prehash is true");
        assertTrue(isValid, "Signature not valid");
    }

    function test_p256_signature_non_extractable() external {
        (bytes memory signature) = _signHashWithP256(hash, true);
        (bytes32 r, bytes32 s, bytes32 qx, bytes32 qy, bool prehash) = signature._unpackP256Signature();
        bool isValid = webAuthnVerifier.verifyP256Signature(EfficientHashLib.sha2(hash), r, s, qx, qy);

        assertTrue(prehash, "Prehash is false");
        assertTrue(isValid, "Signature not valid");
    }
}
