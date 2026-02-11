import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

/**
 * SHA-256 pad a message to the given block size (64 bytes).
 * Standard padding: msg || 0x80 || zeros || 64-bit big-endian bit length
 */
function sha256Pad(message: Buffer, blockSize: number): Buffer {
  const msgLen = message.length;
  const bitLen = BigInt(msgLen * 8);

  const padded = Buffer.alloc(blockSize);
  message.copy(padded);
  padded[msgLen] = 0x80;

  // Write 64-bit big-endian bit length at the end of the block
  padded.writeBigUInt64BE(bitLen, blockSize - 8);

  return padded;
}

/**
 * Split a BigInt into k limbs of n bits each (little-endian order).
 * Returns decimal string representations.
 */
function bigintToLimbs(value: bigint, n: number, k: number): string[] {
  const mask = (1n << BigInt(n)) - 1n;
  const limbs: string[] = [];
  for (let i = 0; i < k; i++) {
    limbs.push(((value >> BigInt(i * n)) & mask).toString());
  }
  return limbs;
}

/**
 * Generate circuit inputs for RSAVerify(maxByteLength=64, n, k).
 */
function generateInputs(
  keySize: number,
  n: number,
  k: number
): Record<string, string[] | number> {
  // Generate RSA key pair
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: keySize,
    publicExponent: 65537,
    publicKeyEncoding: { type: "pkcs1", format: "der" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });

  // Test message
  const message = Buffer.from("hello world");

  // SHA-256 pad the message to 64 bytes (1 block)
  const paddedMessage = sha256Pad(message, 64);

  // Sign the original message using PKCS#1 v1.5 with SHA-256
  // crypto.sign internally hashes the message, so we pass the original
  const signature = crypto.sign("sha256", message, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  // Extract modulus from public key
  const pubKeyObj = crypto.createPublicKey({
    key: publicKey,
    format: "der",
    type: "pkcs1",
  });
  const jwk = pubKeyObj.export({ format: "jwk" });
  const modulusB64 = jwk.n!;
  const modulusBytes = Buffer.from(modulusB64, "base64url");
  const modulusBigInt = BigInt("0x" + modulusBytes.toString("hex"));

  // Convert signature bytes to BigInt
  const sigBigInt = BigInt("0x" + signature.toString("hex"));

  // Convert to limbs
  const sigLimbs = bigintToLimbs(sigBigInt, n, k);
  const modLimbs = bigintToLimbs(modulusBigInt, n, k);

  // Padded message bytes as decimal strings
  const messageArray = Array.from(paddedMessage).map((b) => b.toString());

  return {
    message: messageArray,
    messageLength: 64,
    signature: sigLimbs,
    modulus: modLimbs,
  };
}

// Generate inputs for RSA-2048 (n=121, k=17)
const rsa2048Inputs = generateInputs(2048, 121, 17);
const rsa2048Dir = path.join(__dirname, "..", "inputs", "rsa_verify_2048");
fs.mkdirSync(rsa2048Dir, { recursive: true });
fs.writeFileSync(
  path.join(rsa2048Dir, "default.json"),
  JSON.stringify(rsa2048Inputs, null, 2)
);
console.log("Generated RSA-2048 inputs:", path.join(rsa2048Dir, "default.json"));

// Generate inputs for RSA-4096 (n=121, k=34)
const rsa4096Inputs = generateInputs(4096, 121, 34);
const rsa4096Dir = path.join(__dirname, "..", "inputs", "rsa_verify_4096");
fs.mkdirSync(rsa4096Dir, { recursive: true });
fs.writeFileSync(
  path.join(rsa4096Dir, "default.json"),
  JSON.stringify(rsa4096Inputs, null, 2)
);
console.log("Generated RSA-4096 inputs:", path.join(rsa4096Dir, "default.json"));
