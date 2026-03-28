/**
 * Generate complete test vectors for Move unit tests.
 * Outputs: proof_bytes, public_inputs_bytes, vk_bytes, ed25519 pubkey, signature
 */

import { readFileSync, writeFileSync } from "fs";
import nacl from "tweetnacl";

// Load sui_format.json
const data = JSON.parse(readFileSync("build/sui_format.json", "utf8"));

const proofBytes = Buffer.from(data.proof_hex, "hex");
const inputsBytes = Buffer.from(data.public_inputs_hex, "hex");

// Deterministic Ed25519 keypair (seed = 32 bytes, first byte = 42)
const seed = new Uint8Array(32);
seed[0] = 42;
const keypair = nacl.sign.keyPair.fromSeed(seed);

// Message = proof_bytes || public_inputs_bytes (matches Move contract)
const message = Buffer.concat([proofBytes, inputsBytes]);

// Sign
const signature = nacl.sign.detached(message, keypair.secretKey);

// Verify locally
const verified = nacl.sign.detached.verify(message, signature, keypair.publicKey);
if (!verified) throw new Error("Local Ed25519 verification failed");

const pubkeyHex = Buffer.from(keypair.publicKey).toString("hex");
const sigHex = Buffer.from(signature).toString("hex");

console.log("=== Move Test Vector Constants ===\n");

console.log(`// VK bytes for prepare_verifying_key (${data.vk_hex.length / 2} bytes)`);
console.log(`const VK_BYTES: vector<u8> = x"${data.vk_hex}";\n`);

console.log(`// Groth16 proof (${proofBytes.length} bytes)`);
console.log(`const PROOF_BYTES: vector<u8> = x"${data.proof_hex}";\n`);

console.log(`// Public inputs (${inputsBytes.length} bytes, 4 x 32 LE)`);
console.log(`const PUBLIC_INPUTS_BYTES: vector<u8> = x"${data.public_inputs_hex}";\n`);

console.log(`// TEE Ed25519 pubkey (32 bytes)`);
console.log(`const TEE_PUBKEY: vector<u8> = x"${pubkeyHex}";\n`);

console.log(`// Ed25519 signature over (proof || inputs) (64 bytes)`);
console.log(`const TEE_SIGNATURE: vector<u8> = x"${sigHex}";\n`);

console.log(`// Local verification: ${verified}`);

// Save as JSON too
const vectors = {
  vk_hex: data.vk_hex,
  proof_hex: data.proof_hex,
  public_inputs_hex: data.public_inputs_hex,
  tee_pubkey_hex: pubkeyHex,
  tee_signature_hex: sigHex,
  public_signals: data.public_signals,
};

writeFileSync("build/test_vectors.json", JSON.stringify(vectors, null, 2));
console.log("\nSaved to build/test_vectors.json");
