/**
 * snarkjs -> Sui (Arkworks) Groth16 format converter for Abyssal.
 *
 * Ported from SuiCryptoLib circuits/poc/format_for_sui.mjs with additions:
 * - Outputs raw VK bytes for prepare_verifying_key (Move test extracts 4 pvk components)
 * - Outputs proof and public inputs in Sui format
 *
 * Sui's groth16 module uses Arkworks canonical compressed serialization:
 * - G1 compressed: 32 bytes (x LE, y-sign in last byte bit 7)
 * - G2 compressed: 64 bytes (x.c0 LE || x.c1 LE, y-sign in last byte of c1 bit 7)
 * - Scalar: 32 bytes LE
 */

import { readFileSync, writeFileSync } from "fs";

// BN254 base field prime
const BN254_P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function bigintToBytes32LE(value) {
  const buf = new Uint8Array(32);
  let v = BigInt(value);
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// G1 compressed: 32 bytes (x LE, y-sign bit 7 of last byte)
function serializeG1Compressed(point) {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);

  if (x === 0n && y === 0n) {
    const buf = new Uint8Array(32);
    buf[31] = 0x40;
    return buf;
  }

  const xBytes = bigintToBytes32LE(x);
  if (y > BN254_P / 2n) {
    xBytes[31] |= 0x80;
  }
  return xBytes;
}

// G2 compressed: 64 bytes (x.c0 LE || x.c1 LE, y-sign bit 7 of c1 last byte)
// Fp2 lexicographic: compare c1 first, then c0
function serializeG2Compressed(point) {
  const xC0 = BigInt(point[0][0]);
  const xC1 = BigInt(point[0][1]);
  const yC0 = BigInt(point[1][0]);
  const yC1 = BigInt(point[1][1]);

  if (xC0 === 0n && xC1 === 0n && yC0 === 0n && yC1 === 0n) {
    const buf = new Uint8Array(64);
    buf[63] = 0x40;
    return buf;
  }

  const c0Bytes = bigintToBytes32LE(xC0);
  const c1Bytes = bigintToBytes32LE(xC1);

  let yNeg;
  if (yC1 !== 0n) {
    yNeg = yC1 > BN254_P / 2n;
  } else {
    yNeg = yC0 > BN254_P / 2n;
  }

  if (yNeg) {
    c1Bytes[31] |= 0x80;
  }

  const result = new Uint8Array(64);
  result.set(c0Bytes, 0);
  result.set(c1Bytes, 32);
  return result;
}

// Proof: A(G1, 32) || B(G2, 64) || C(G1, 32) = 128 bytes
function convertProof(proof) {
  const a = serializeG1Compressed(proof.pi_a);
  const b = serializeG2Compressed(proof.pi_b);
  const c = serializeG1Compressed(proof.pi_c);

  const result = new Uint8Array(128);
  result.set(a, 0);
  result.set(b, 32);
  result.set(c, 96);
  return result;
}

// Public inputs: each signal as 32-byte LE scalar
function convertPublicInputs(publicSignals) {
  const result = new Uint8Array(publicSignals.length * 32);
  for (let i = 0; i < publicSignals.length; i++) {
    const scalar = bigintToBytes32LE(BigInt(publicSignals[i]));
    result.set(scalar, i * 32);
  }
  return result;
}

// Raw VK in Arkworks compressed format for prepare_verifying_key:
// alpha(G1, 32) || beta(G2, 64) || gamma(G2, 64) || delta(G2, 64)
// || IC_count(u64 LE, 8) || IC[0](G1, 32) || IC[1](G1, 32) || ...
function convertVK(vk) {
  const alpha = serializeG1Compressed(vk.vk_alpha_1);
  const beta = serializeG2Compressed(vk.vk_beta_2);
  const gamma = serializeG2Compressed(vk.vk_gamma_2);
  const delta = serializeG2Compressed(vk.vk_delta_2);

  const icLen = vk.IC.length;
  const icLenBytes = new Uint8Array(8);
  let len = BigInt(icLen);
  for (let i = 0; i < 8; i++) {
    icLenBytes[i] = Number(len & 0xffn);
    len >>= 8n;
  }

  const icBytes = new Uint8Array(icLen * 32);
  for (let i = 0; i < icLen; i++) {
    const ic = serializeG1Compressed(vk.IC[i]);
    icBytes.set(ic, i * 32);
  }

  const totalLen = 32 + 64 + 64 + 64 + 8 + icLen * 32;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  result.set(alpha, offset); offset += 32;
  result.set(beta, offset); offset += 64;
  result.set(gamma, offset); offset += 64;
  result.set(delta, offset); offset += 64;
  result.set(icLenBytes, offset); offset += 8;
  result.set(icBytes, offset);

  return result;
}

// --- Main ---

const proof = JSON.parse(readFileSync("build/proof.json", "utf8"));
const publicSignals = JSON.parse(readFileSync("build/public.json", "utf8"));
const vk = JSON.parse(readFileSync("build/vk.json", "utf8"));

const proofBytes = convertProof(proof);
const publicInputsBytes = convertPublicInputs(publicSignals);
const vkBytes = convertVK(vk);

console.log("=== Abyssal Sui Groth16 Format ===\n");

console.log(`Proof points (${proofBytes.length} bytes):`);
console.log(`  x"${bytesToHex(proofBytes)}"\n`);

console.log(`Public inputs (${publicInputsBytes.length} bytes):`);
console.log(`  x"${bytesToHex(publicInputsBytes)}"\n`);

console.log(`Raw VK for prepare_verifying_key (${vkBytes.length} bytes):`);
console.log(`  x"${bytesToHex(vkBytes)}"\n`);

console.log("--- Move test usage ---");
console.log("// In test: call prepare_verifying_key to get 4 pvk components,");
console.log("// then pvk_to_bytes to extract them for create_vault.");
console.log("let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &VK_BYTES);");
console.log("let components = groth16::pvk_to_bytes(pvk);");
console.log("");

// Save structured output
const output = {
  proof_hex: bytesToHex(proofBytes),
  public_inputs_hex: bytesToHex(publicInputsBytes),
  vk_hex: bytesToHex(vkBytes),
  proof_length: proofBytes.length,
  public_inputs_length: publicInputsBytes.length,
  vk_length: vkBytes.length,
  public_signals: publicSignals,
};

writeFileSync("build/sui_format.json", JSON.stringify(output, null, 2));
console.log("Saved to build/sui_format.json");
