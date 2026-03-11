import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { Hex, AbiParameters } from "ox";

/**
 * WebAuthn FFI script for Foundry tests.
 *
 * Usage: npx tsx script/WebAuthn.ts <digest_hex>
 *
 * Generates a P256 key pair, constructs valid WebAuthn authenticatorData and
 * clientDataJSON, signs the WebAuthn message, and outputs:
 *   abi.encode(WebAuthnAuth) || qx(32) || qy(32)
 *
 * Compatible with Solady's WebAuthn.tryDecodeAuth() (tolerates trailing bytes).
 */

// --- helpers ----------------------------------------------------------------

function toBytes32Hex(val: Uint8Array): string {
    return Buffer.from(val).toString("hex").padStart(64, "0");
}

/** Base64url encode without padding (matches Solady Base64.encode(data, true, true)) */
function base64urlNoPad(data: Uint8Array): string {
    return Buffer.from(data)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// --- args -------------------------------------------------------------------

const args = process.argv.slice(2);
const digestHex = args[0];

if (!digestHex) {
    console.error("Usage: WebAuthn.ts <digest_hex>");
    process.exit(1);
}

// --- key generation ---------------------------------------------------------

const privateKey = p256.utils.randomPrivateKey();
const publicKey = p256.getPublicKey(privateKey, false);
const qx = publicKey.slice(1, 33);
const qy = publicKey.slice(33, 65);

// --- WebAuthn auth data construction ----------------------------------------

// The challenge passed to WebAuthn.verify() is toBytes(hash) — raw 32 bytes.
// Solady encodes it as base64url-no-pad before matching against clientDataJSON.
const challengeBytes = Hex.toBytes(digestHex as `0x${string}`);
const challengeB64 = base64urlNoPad(challengeBytes);

// rpIdHash = sha256("localhost")
const rpIdHash = sha256(new TextEncoder().encode("localhost"));
// flags: UP (0x01) | UV (0x04) = 0x05
const flags = new Uint8Array([0x05]);
// signCount: 1
const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
// authenticatorData = rpIdHash(32) || flags(1) || signCount(4) = 37 bytes
const authenticatorData = new Uint8Array([...rpIdHash, ...flags, ...signCount]);

const origin = "http://localhost:5173";

const clientDataJSON = `{"type":"webauthn.get","challenge":"${challengeB64}","origin":"${origin}","crossOrigin":false}`;

// Solady prepends '"challenge":"' to the encoded value and matches the whole thing.
// So challengeIndex must point to the '"' before "challenge" in the JSON.
// Similarly, typeIndex must point to the '"' before "type" in the JSON.
const challengeIndex = clientDataJSON.indexOf('"challenge"');
const typeIndex = clientDataJSON.indexOf('"type"');

// --- signing ----------------------------------------------------------------

// WebAuthn signing message = sha256(authenticatorData || sha256(clientDataJSON))
const clientDataHash = sha256(new TextEncoder().encode(clientDataJSON));
const signedData = new Uint8Array([...authenticatorData, ...clientDataHash]);
const messageHash = sha256(signedData);

const signature = p256.sign(messageHash, privateKey, { lowS: true });
const r = signature.toCompactRawBytes().slice(0, 32);
const s = signature.toCompactRawBytes().slice(32, 64);

// --- ABI encode (matches Solidity abi.encode(WebAuthnAuth)) -----------------

const authDataHex = ("0x" + Buffer.from(authenticatorData).toString("hex")) as `0x${string}`;
const rHex = ("0x" + toBytes32Hex(r)) as `0x${string}`;
const sHex = ("0x" + toBytes32Hex(s)) as `0x${string}`;

const encoded = AbiParameters.encode(
    AbiParameters.from(
        "(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s)"
    ),
    [[authDataHex, clientDataJSON, BigInt(challengeIndex), BigInt(typeIndex), rHex, sHex]]
);

// Output: abi.encode(WebAuthnAuth) || qx || qy
const output = encoded + toBytes32Hex(qx) + toBytes32Hex(qy);

process.stdout.write(output);
