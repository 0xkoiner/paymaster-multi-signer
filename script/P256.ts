import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { Hex } from "ox";

function toBytes32Hex(val: Uint8Array): string {
    return Buffer.from(val).toString("hex").padStart(64, "0");
}

const args = process.argv.slice(2);
const digestHex = args[0];
const keyType = args[1];

if (!digestHex || !keyType) {
    console.error("Usage: P256.ts <digest_hex> <extractable|non-extractable>");
    process.exit(1);
}

const nonExtractable = keyType === "non-extractable";

const privateKey = p256.utils.randomPrivateKey();
const publicKey = p256.getPublicKey(privateKey, false);
const qx = publicKey.slice(1, 33);
const qy = publicKey.slice(33, 65);

const digest = Hex.toBytes(digestHex as `0x${string}`);

const messageToSign = nonExtractable ? sha256(digest) : digest;

const signature = p256.sign(messageToSign, privateKey, { lowS: true });
const r = signature.toCompactRawBytes().slice(0, 32);
const s = signature.toCompactRawBytes().slice(32, 64);

// Output: r || s || qx || qy [|| 0x01]
let output = toBytes32Hex(r) + toBytes32Hex(s) + toBytes32Hex(qx) + toBytes32Hex(qy);

if (nonExtractable) {
    output += "01";
}

process.stdout.write("0x" + output);
