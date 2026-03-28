import { readFileSync } from "fs";
import { createHash } from "crypto";

/**
 * Circuit hash digests for on-chain registration.
 */
export interface CircuitHashes {
  /** SHA-256(wasm_plaintext), 32 bytes */
  wasmHash: Uint8Array;
  /** SHA-256(SHA-256(wasm_plaintext)), 32 bytes — stored in VaultConfig.wasm_double_hash */
  wasmDoubleHash: Uint8Array;
}

/**
 * Compute SHA-256 hashes for a circuit's wasm file.
 *
 * The wasm_double_hash (SHA-256 of SHA-256) is stored on-chain in VaultConfig
 * and verified by TEE enclaves when loading the circuit to ensure integrity.
 *
 * @param wasmPath - Path to the compiled circuit .wasm file
 * @returns Hash digests for on-chain registration
 */
export async function computeCircuitHashes(
  wasmPath: string,
): Promise<CircuitHashes> {
  const wasmBytes = readFileSync(wasmPath);

  const wasmHash = createHash("sha256").update(wasmBytes).digest();
  const wasmDoubleHash = createHash("sha256").update(wasmHash).digest();

  return {
    wasmHash: new Uint8Array(wasmHash),
    wasmDoubleHash: new Uint8Array(wasmDoubleHash),
  };
}
