// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../data/Constants.sol";
import { Helpers } from "../helpers/Helpers.t.sol";
import { KeyLib } from "../../contracts/library/KeyLib.sol";
import { WebAuthn } from "../../contracts/library/WebAuthn.sol";
import { Key, SignerType } from "../../contracts/type/Types.sol";
import { IEntryPoint } from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";

contract TestCoverageWebAuthnVerifier is Helpers {
    using KeyLib for *;

    // ------------------------------------------------------------------------------------
    //
    //                                        Storage
    //
    // ------------------------------------------------------------------------------------

    P256PubKey internal pK;

    function setUp() public override {
        super.setUp();
        _ethc();
    }

    // ------------------------------------------------------------------------------------
    //
    //    verifySignature — explicit params (WebAuthnVerifier line 28)
    //
    // ------------------------------------------------------------------------------------

    function test_verifySignature_explicit_params() external {
        bytes32 hash = keccak256("test-challenge");

        (bytes memory signature, P256PubKey memory pubKey) = _signHashWithWebAuthn(hash);
        pK = pubKey;

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(signature);

        bool isValid = webAuthnVerifier.verifySignature(
            hash,
            true,
            auth.authenticatorData,
            auth.clientDataJSON,
            auth.challengeIndex,
            auth.typeIndex,
            auth.r,
            auth.s,
            pK.qx,
            pK.qy
        );

        assertTrue(isValid, "Explicit param verification should pass");
    }

    // ------------------------------------------------------------------------------------
    //
    //    verifyCompactSignature (WebAuthnVerifier line 97)
    //
    // ------------------------------------------------------------------------------------

    function test_verifyCompactSignature() external {
        bytes32 hash = keccak256("test-compact");

        (bytes memory signature, P256PubKey memory pubKey) = _signHashWithWebAuthn(hash);
        pK = pubKey;

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(signature);

        bytes memory compactEncoded = WebAuthn.tryEncodeAuthCompact(auth);

        // Convert bytes32 challenge to bytes for compact variant
        bytes memory challengeBytes = new bytes(32);
        assembly {
            mstore(add(challengeBytes, 32), hash)
        }

        bool isValid = webAuthnVerifier.verifyCompactSignature(challengeBytes, true, compactEncoded, pK.qx, pK.qy);

        assertTrue(isValid, "Compact signature verification should pass");
    }
}
