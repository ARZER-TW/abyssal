// Circuit state manager.
// Holds paths to the zkey and wasm files loaded via admin endpoint.
// Verifies wasm_double_hash integrity on load.

import { readFileSync } from "fs";
import { createHash } from "crypto";

let circuitLoaded = false;
let zkeyPath: string | null = null;
let wasmPath: string | null = null;
let storedWasmDoubleHash: string | null = null;

/**
 * Load circuit files and verify wasm integrity via double SHA-256 hash.
 *
 * @param zkey - Path to the .zkey file (proving key)
 * @param wasm - Path to the .wasm file (witness calculator)
 * @param expectedWasmDoubleHash - Optional hex string of expected SHA-256(SHA-256(wasm)).
 *   If provided and mismatch, throws an error (TEE refuses to load tampered circuit).
 *   If omitted (hackathon mode), computes and stores the hash without verification.
 */
export function loadCircuit(
  zkey: string,
  wasm: string,
  expectedWasmDoubleHash?: string,
): void {
  // Read wasm and compute double hash
  const wasmBytes = readFileSync(wasm);
  const wasmHash = createHash("sha256").update(wasmBytes).digest();
  const wasmDoubleHash = createHash("sha256").update(wasmHash).digest();
  const computedHex = wasmDoubleHash.toString("hex");

  if (expectedWasmDoubleHash) {
    const expected = expectedWasmDoubleHash.startsWith("0x")
      ? expectedWasmDoubleHash.slice(2)
      : expectedWasmDoubleHash;
    if (computedHex !== expected.toLowerCase()) {
      throw new Error(
        `wasm_double_hash mismatch: expected ${expected}, got ${computedHex}`,
      );
    }
  }

  zkeyPath = zkey;
  wasmPath = wasm;
  storedWasmDoubleHash = computedHex;
  circuitLoaded = true;
}

export function isCircuitLoaded(): boolean {
  return circuitLoaded;
}

export function getZkeyPath(): string {
  if (!zkeyPath) throw new Error("Circuit not loaded");
  return zkeyPath;
}

export function getWasmPath(): string {
  if (!wasmPath) throw new Error("Circuit not loaded");
  return wasmPath;
}

export function getWasmDoubleHash(): string {
  if (!storedWasmDoubleHash) throw new Error("Circuit not loaded");
  return storedWasmDoubleHash;
}
