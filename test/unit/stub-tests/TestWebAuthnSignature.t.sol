// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import { Constants } from "../../data/Constants.sol";
import { Helpers } from "../../helpers/Helpers.t.sol";
import { KeyLib } from "../../../contracts/library/KeyLib.sol";
import { WebAuthn } from "../../../contracts/library/WebAuthn.sol";
import { EfficientHashLib } from "@solady/src/utils/EfficientHashLib.sol";

contract TestWebAuthnSignature is Helpers {
    using KeyLib for *;

    WebAuthn.WebAuthnAuth internal webAuthnAuth;
    bytes32 internal constant qx = 0x55f434ca0c4b938c457f673a570126a26ea03633b19f36047be2ffa005c40b50;
    bytes32 internal constant qy = 0x22e25237817804ecb4d942f6b03ea37281949283170a50ca815a6be3dd8e9333;
    bytes32 internal constant hash = 0x621921c7e1a80386e084525814831fedbcdf082c4128ef61dab8bb8a670f6e92;

    function setUp() public override {
        super.setUp();
        _ethc();
    }

    function test_webauthn_signature() external {
        webAuthnAuth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
        webAuthnAuth.clientDataJSON =
            "{\"type\":\"webauthn.get\",\"challenge\":\"Yhkhx-GoA4bghFJYFIMf7bzfCCxBKO9h2ri7imcPbpI\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";
        webAuthnAuth.challengeIndex = 23;
        webAuthnAuth.typeIndex = 1;
        webAuthnAuth.r = 0x2b15cba11f6cb602e77afa982453882a937aa927daffdbbdc061b244cb0d3b28;
        webAuthnAuth.s = 0x19df7755074a49d35fb5b5874e19973a9e4498ee27de4770f80ed12a14b389eb;

        bytes memory signature = _encodeWebAuthn(webAuthnAuth, qx, qy);

        _assert(signature);

        bool isValid = webAuthnVerifier.verifyEncodedSignature(hash, true, signature, qx, qy);
        assertTrue(isValid, "Not valid signature");
    }

    function _assert(bytes memory _signature) internal view {
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(_signature);

        bytes32 decodedQx;
        bytes32 decodedQy;

        uint256 len = _signature.length;
        assembly {
            decodedQy := mload(add(_signature, len))
            decodedQx := mload(add(_signature, sub(len, 0x20)))
        }

        assertEq(decodedQx, qx, "Not same X");
        assertEq(decodedQy, qy, "Not same Y");
        assertEq(auth.authenticatorData, webAuthnAuth.authenticatorData, "Not same authenticatorData");
        assertEq(auth.clientDataJSON, webAuthnAuth.clientDataJSON, "Not same clientDataJSON");
        assertEq(auth.challengeIndex, webAuthnAuth.challengeIndex, "Not same challengeIndex");
        assertEq(auth.typeIndex, webAuthnAuth.typeIndex, "Not same typeIndex");
        assertEq(auth.r, webAuthnAuth.r, "Not same r");
        assertEq(auth.s, webAuthnAuth.s, "Not same s");
    }
}
