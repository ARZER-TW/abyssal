import { BN254_P } from "../constants.ts";

/**
 * Convert a bigint to 32-byte little-endian Uint8Array.
 */
export function bigintToBytes32LE(value: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let v = value;
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

/**
 * Compress a BN254 G1 point (x, y as decimal strings) to 32 bytes Arkworks format.
 */
export function serializeG1Compressed(point: string[]): Uint8Array {
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

/**
 * Compress a BN254 G2 point to 64 bytes Arkworks format.
 * point = [[xC0, xC1], [yC0, yC1]] as decimal strings.
 */
export function serializeG2Compressed(point: string[][]): Uint8Array {
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
 * Serialize a snarkjs verification_key.json object into Arkworks compressed VK bytes.
 *
 * Format: alpha(G1,32) || beta(G2,64) || gamma(G2,64) || delta(G2,64)
 *         || IC_count(u64 LE,8) || IC[0](G1,32) || IC[1](G1,32) || ...
 */
export function serializeVkToArkworks(vk: {
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}): Uint8Array {
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
  vkBytes.set(alpha, offset);
  offset += 32;
  vkBytes.set(beta, offset);
  offset += 64;
  vkBytes.set(gamma, offset);
  offset += 64;
  vkBytes.set(delta, offset);
  offset += 64;
  vkBytes.set(icLenBytes, offset);
  offset += 8;
  vkBytes.set(icBytes, offset);

  return vkBytes;
}

/**
 * Parse BCS-encoded vector<vector<u8>> returned by pvk_to_bytes.
 */
export function parseBcsVectorOfVectorU8(
  data: Uint8Array,
): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  let offset = 0;

  function readUleb128(): number {
    let result = 0;
    let shift = 0;
    while (true) {
      const byte = data[offset++];
      result |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }
    return result;
  }

  function readVecU8(): Uint8Array {
    const len = readUleb128();
    const bytes = data.slice(offset, offset + len);
    offset += len;
    return bytes;
  }

  const outerLen = readUleb128();
  if (outerLen !== 4) {
    throw new Error(`Expected 4 pvk components, got ${outerLen}`);
  }

  return [readVecU8(), readVecU8(), readVecU8(), readVecU8()];
}
