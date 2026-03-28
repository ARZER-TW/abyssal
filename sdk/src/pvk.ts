import { readFileSync } from "fs";

const BN254_P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/**
 * Processed verification key components for pvk_from_bytes.
 * These are passed to prepare_verifying_key on-chain, which internally
 * computes the 4 pvk components.
 */
export interface PvkComponents {
  /** Raw VK bytes in Arkworks compressed format (for prepare_verifying_key) */
  vkBytes: Uint8Array;
  /** Number of IC points (= public inputs + 1) */
  icCount: number;
}

function bigintToBytes32LE(value: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let v = value;
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function serializeG1Compressed(point: string[]): Uint8Array {
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

function serializeG2Compressed(point: string[][]): Uint8Array {
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

  let yNeg: boolean;
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

/**
 * Compute raw VK bytes in Arkworks compressed format from snarkjs vk.json.
 *
 * The output is passed to `prepare_verifying_key(&bn254(), &vk_bytes)` on-chain
 * (or via dry-run) to produce the 4 pvk components for `pvk_from_bytes`.
 *
 * Format: alpha(G1,32) || beta(G2,64) || gamma(G2,64) || delta(G2,64)
 *         || IC_count(u64 LE,8) || IC[0](G1,32) || IC[1](G1,32) || ...
 *
 * @param vkJsonPath - Path to snarkjs verification_key.json
 */
export async function computePvkComponents(
  vkJsonPath: string,
): Promise<PvkComponents> {
  const vk = JSON.parse(readFileSync(vkJsonPath, "utf8"));

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
  const vkBytes = new Uint8Array(totalLen);
  let offset = 0;
  vkBytes.set(alpha, offset); offset += 32;
  vkBytes.set(beta, offset); offset += 64;
  vkBytes.set(gamma, offset); offset += 64;
  vkBytes.set(delta, offset); offset += 64;
  vkBytes.set(icLenBytes, offset); offset += 8;
  vkBytes.set(icBytes, offset);

  return { vkBytes, icCount: icLen };
}

/**
 * Convert a snarkjs proof to Sui proof_points bytes (128 bytes).
 * Format: A(G1,32) || B(G2,64) || C(G1,32)
 */
export function convertProofToSui(proof: {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}): Uint8Array {
  const a = serializeG1Compressed(proof.pi_a);
  const b = serializeG2Compressed(proof.pi_b);
  const c = serializeG1Compressed(proof.pi_c);

  const result = new Uint8Array(128);
  result.set(a, 0);
  result.set(b, 32);
  result.set(c, 96);
  return result;
}

/**
 * Convert public signals to Sui public_proof_inputs bytes.
 * Each signal is a 32-byte LE scalar.
 */
export function convertPublicInputsToSui(
  publicSignals: string[],
): Uint8Array {
  const result = new Uint8Array(publicSignals.length * 32);
  for (let i = 0; i < publicSignals.length; i++) {
    const scalar = bigintToBytes32LE(BigInt(publicSignals[i]));
    result.set(scalar, i * 32);
  }
  return result;
}
