pragma circom 2.1.6;

include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "circomlib/circuits/bitify.circom";

/// @title Bits2Limbs
/// @notice Converts big-endian SHA-256 output bits to little-endian n-bit RSA limbs.
/// @param n Number of bits per limb
/// @param k Number of limbs
/// @param totalBits Number of input bits (256 for SHA-256)
template Bits2Limbs(n, k, totalBits) {
    signal input bits[totalBits];
    signal output limbs[k];

    component b2n[k];
    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitPos = i * n + j;
            if (bitPos < totalBits) {
                // Map LSB-first limb bit position to big-endian SHA output index
                b2n[i].in[j] <== bits[totalBits - 1 - bitPos];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        limbs[i] <== b2n[i].out;
    }
}

/// @title RSAVerify
/// @notice Minimal RSA signature verification: SHA-256 hash + RSA verify.
///         Verifies that signature is a valid PKCS#1 v1.5 RSA-SHA256 signature
///         over the given message, under the given public modulus.
/// @param maxByteLength Max SHA-256 padded message length in bytes (must be multiple of 64)
/// @param n Bits per RSA limb (recommended: 121)
/// @param k Number of RSA limbs (17 for RSA-2048, 34 for RSA-4096)
template RSAVerify(maxByteLength, n, k) {
    signal input message[maxByteLength];
    signal input messageLength;
    signal input signature[k];
    signal input modulus[k];

    // Step 1: SHA-256 hash the padded message
    component sha = Sha256Bytes(maxByteLength);
    for (var i = 0; i < maxByteLength; i++) {
        sha.paddedIn[i] <== message[i];
    }
    sha.paddedInLength <== messageLength;

    // Step 2: Convert 256-bit big-endian hash to k little-endian n-bit limbs
    component bits2limbs = Bits2Limbs(n, k, 256);
    for (var i = 0; i < 256; i++) {
        bits2limbs.bits[i] <== sha.out[i];
    }

    // Step 3: Verify RSA signature against the hash
    component rsaVerifier = RSAVerifier65537(n, k);
    for (var i = 0; i < k; i++) {
        rsaVerifier.message[i] <== bits2limbs.limbs[i];
        rsaVerifier.signature[i] <== signature[i];
        rsaVerifier.modulus[i] <== modulus[i];
    }
}
