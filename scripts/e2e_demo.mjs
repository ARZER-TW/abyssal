/**
 * Abyssal E2E Demo Script
 *
 * Full flow on Sui testnet:
 * 1. Deploy vault with real VK from credit_score circuit
 * 2. Register TEE enclave pubkey
 * 3. Call TEE /prove with test inputs (vault_id_field derived from actual vault)
 * 4. Submit proof on-chain
 * 5. Verify proof
 * 6. Consume proof with result
 *
 * Prerequisites:
 * - TEE server running on localhost:3001 with circuit loaded
 * - Sui CLI configured with testnet and funded address
 */

import { SuiClient } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { readFileSync } from "fs";
import { createHash } from "crypto";

// --- Constants ---
const PACKAGE_ID = "0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777";
const SEAL_POLICY_ID = "0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8";
const TEE_ENDPOINT = "http://localhost:3001";
const RPC_URL = "https://fullnode.testnet.sui.io:443";
const BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const client = new SuiClient({ url: RPC_URL });

// Load signer from sui keystore (second key = ptb-workshop, active address)
const keystoreRaw = readFileSync(
  `${process.env.HOME}/.sui/sui_config/sui.keystore`,
  "utf8",
);
const keys = JSON.parse(keystoreRaw);
// The active address is ptb-workshop (index 1 in the fixed keystore)
const keypair = Ed25519Keypair.fromSecretKey(
  Buffer.from(keys[1], "base64").slice(1), // strip scheme flag byte
);

console.log("Deployer:", keypair.toSuiAddress());

// --- Format helpers ---
function bigintToBytes32LE(value) {
  const buf = Buffer.alloc(32);
  let v = BigInt(value);
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function serializeG1Compressed(point) {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  if (x === 0n && y === 0n) {
    const buf = Buffer.alloc(32);
    buf[31] = 0x40;
    return buf;
  }
  const xBytes = bigintToBytes32LE(x);
  if (y > BN254_P / 2n) xBytes[31] |= 0x80;
  return xBytes;
}

function serializeG2Compressed(point) {
  const xC0 = BigInt(point[0][0]);
  const xC1 = BigInt(point[0][1]);
  const yC0 = BigInt(point[1][0]);
  const yC1 = BigInt(point[1][1]);
  if (xC0 === 0n && xC1 === 0n && yC0 === 0n && yC1 === 0n) {
    const buf = Buffer.alloc(64);
    buf[63] = 0x40;
    return buf;
  }
  const c0Bytes = bigintToBytes32LE(xC0);
  const c1Bytes = bigintToBytes32LE(xC1);
  const halfP = BN254_P / 2n;
  const yNeg = yC1 !== 0n ? yC1 > halfP : yC0 > halfP;
  if (yNeg) c1Bytes[31] |= 0x80;
  const result = Buffer.alloc(64);
  c0Bytes.copy(result, 0);
  c1Bytes.copy(result, 32);
  return result;
}

function convertVK(vk) {
  const alpha = serializeG1Compressed(vk.vk_alpha_1);
  const beta = serializeG2Compressed(vk.vk_beta_2);
  const gamma = serializeG2Compressed(vk.vk_gamma_2);
  const delta = serializeG2Compressed(vk.vk_delta_2);
  const icLen = vk.IC.length;
  const icLenBuf = Buffer.alloc(8);
  icLenBuf.writeBigUInt64LE(BigInt(icLen));
  const icBufs = vk.IC.map((ic) => serializeG1Compressed(ic));
  return Buffer.concat([alpha, beta, gamma, delta, icLenBuf, ...icBufs]);
}

function hexToBytes(hex) {
  return Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex");
}

// --- BCS helpers ---
function readUleb128(data, offset) {
  let result = 0, shift = 0, o = offset;
  while (true) {
    const byte = data[o++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return [result, o];
}

function parseBcsVecOfVecU8(data) {
  let offset = 0;
  let [outerLen, o1] = readUleb128(data, offset);
  offset = o1;
  const result = [];
  for (let i = 0; i < outerLen; i++) {
    let [innerLen, o2] = readUleb128(data, offset);
    offset = o2;
    result.push(data.slice(offset, offset + innerLen));
    offset += innerLen;
  }
  return result;
}

// ====================================================================
// Step 1: Deploy Vault
// ====================================================================
async function deployVault() {
  console.log("\n=== Step 1: Deploy Vault ===");

  const vk = JSON.parse(
    readFileSync("circuits/credit_score/build/vk.json", "utf8"),
  );
  const vkBytes = convertVK(vk);
  console.log("VK bytes:", vkBytes.length, "bytes");

  // Get pvk components via devInspect
  const inspectTx = new Transaction();
  const curve = inspectTx.moveCall({ target: "0x2::groth16::bn254" });
  const pvk = inspectTx.moveCall({
    target: "0x2::groth16::prepare_verifying_key",
    arguments: [curve[0], inspectTx.pure.vector("u8", Array.from(vkBytes))],
  });
  inspectTx.moveCall({
    target: "0x2::groth16::pvk_to_bytes",
    arguments: [pvk[0]],
  });

  const inspectResult = await client.devInspectTransactionBlock({
    transactionBlock: inspectTx,
    sender: keypair.toSuiAddress(),
  });

  if (!inspectResult.results?.[2]?.returnValues) {
    throw new Error("devInspect failed for prepare_verifying_key");
  }

  const pvkRaw = new Uint8Array(inspectResult.results[2].returnValues[0][0]);
  const components = parseBcsVecOfVecU8(pvkRaw);
  console.log(
    "PVK components:",
    components.map((c) => c.length + "B"),
  );

  // Compute wasm_double_hash
  const wasmBytes = readFileSync(
    "circuits/credit_score/build/credit_score_js/credit_score.wasm",
  );
  const wasmHash = createHash("sha256").update(wasmBytes).digest();
  const wasmDoubleHash = createHash("sha256").update(wasmHash).digest();
  console.log("wasm_double_hash:", wasmDoubleHash.toString("hex").slice(0, 16) + "...");

  // Build create_vault PTB
  const tx = new Transaction();
  tx.moveCall({
    target: `${PACKAGE_ID}::abyssal_registry::create_vault`,
    arguments: [
      tx.pure.vector("u8", Array.from(components[0])),
      tx.pure.vector("u8", Array.from(components[1])),
      tx.pure.vector("u8", Array.from(components[2])),
      tx.pure.vector("u8", Array.from(components[3])),
      tx.pure.vector("u8", Array.from(wasmDoubleHash)),
      tx.pure.vector("u8", [0x12, 0x34]), // dummy pk_blob_id
      tx.pure.vector("u8", [0x56, 0x78]), // dummy wasm_blob_id
      tx.pure.vector("u8", [0x9a, 0xbc]), // dummy circuit_source_blob_id
      tx.pure.id(SEAL_POLICY_ID),
      tx.pure.u64(28),
      tx.pure.u8(0), // one-time nullifier
      tx.pure.vector("u8", Array.from(Buffer.from("Credit Score Demo"))),
    ],
  });

  const result = await client.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true, showObjectChanges: true },
  });

  const created = result.objectChanges?.find(
    (c) => c.type === "created" && c.objectType?.includes("VaultConfig"),
  );

  if (!created || created.type !== "created") {
    console.error("Object changes:", JSON.stringify(result.objectChanges, null, 2));
    throw new Error("VaultConfig not found in tx result");
  }

  console.log("[OK] Vault deployed:", created.objectId);
  console.log("  Waiting for indexing...");
  await client.waitForTransaction({ digest: result.digest });
  return { vaultId: created.objectId, wasmDoubleHash };
}

// ====================================================================
// Step 2: Register TEE Enclave
// ====================================================================
async function registerEnclave(vaultId, wasmDoubleHash) {
  console.log("\n=== Step 2: Register TEE Enclave ===");

  // Get TEE pubkey
  const health = await fetch(`${TEE_ENDPOINT}/health`).then((r) => r.json());
  const teePubkey = hexToBytes(health.pubkey);
  console.log("TEE pubkey:", health.pubkey.slice(0, 16) + "...");

  const tx = new Transaction();
  tx.moveCall({
    target: `${PACKAGE_ID}::abyssal_registry::register_enclave`,
    arguments: [
      tx.object(vaultId),
      tx.pure.vector("u8", Array.from(teePubkey)),
      tx.pure.vector("u8", Array.from(wasmDoubleHash)),
    ],
  });

  const regResult = await client.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true },
  });

  console.log("[OK] Enclave registered");
  console.log("  Waiting for indexing...");
  await client.waitForTransaction({ digest: regResult.digest });
}

// ====================================================================
// Step 3: Generate Proof via TEE
// ====================================================================
async function generateProof(vaultId) {
  console.log("\n=== Step 3: Generate Proof via TEE ===");

  // Get current epoch
  const state = await client.getLatestSuiSystemState();
  const currentEpoch = Number(state.epoch);
  console.log("Current Sui epoch:", currentEpoch);

  // Compute vault_id_field = vault_id_u256 % BN254_R (match contract logic)
  // CRITICAL: Move bytes32_to_u256 interprets bytes as LITTLE-ENDIAN.
  // Sui hex display is big-endian, so we must reverse byte order.
  const vaultIdHex = vaultId.startsWith("0x") ? vaultId.slice(2) : vaultId;
  const vaultIdBytes = Buffer.from(vaultIdHex, "hex");
  let vaultIdU256 = 0n;
  for (let i = 0; i < 32; i++) {
    vaultIdU256 |= BigInt(vaultIdBytes[i]) << BigInt(i * 8);
  }
  const vaultIdField = vaultIdU256 % BN254_R;

  // Test inputs
  const income = 5000;
  const monthlyExpenses = 4800;
  const yearsOfHistory = 15;
  const resultValue = 300 + (income - monthlyExpenses) + yearsOfHistory * 10;
  console.log("Computed credit score:", resultValue);

  const privateInputs = {
    user_secret: "12345678901234567890",
    vault_id_field: vaultIdField.toString(),
    epoch: currentEpoch.toString(),
    result_value: resultValue.toString(),
    result_salt: "999888777666555444",
    income: income.toString(),
    monthly_expenses: monthlyExpenses.toString(),
    years_of_history: yearsOfHistory.toString(),
  };

  console.log("Calling TEE /prove...");
  const response = await fetch(`${TEE_ENDPOINT}/prove`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ privateInputs }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`TEE /prove failed: ${response.status} ${err}`);
  }

  const teeResult = await response.json();
  console.log(
    "[OK] Proof generated:",
    teeResult.proof_hex.length / 2,
    "bytes proof,",
    teeResult.public_inputs_hex.length / 2,
    "bytes inputs",
  );

  return teeResult;
}

// ====================================================================
// Step 4: Submit Proof On-Chain
// ====================================================================
async function submitProof(vaultId, teeResult) {
  console.log("\n=== Step 4: Submit Proof On-Chain ===");

  const tx = new Transaction();
  const vaultProof = tx.moveCall({
    target: `${PACKAGE_ID}::abyssal_registry::submit_proof`,
    arguments: [
      tx.object(vaultId),
      tx.pure.vector("u8", Array.from(hexToBytes(teeResult.pubkey_hex))),
      tx.pure.vector("u8", Array.from(hexToBytes(teeResult.proof_hex))),
      tx.pure.vector("u8", Array.from(hexToBytes(teeResult.public_inputs_hex))),
      tx.pure.vector("u8", Array.from(hexToBytes(teeResult.signature_hex))),
    ],
  });

  tx.transferObjects([vaultProof[0]], keypair.toSuiAddress());

  const result = await client.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true, showObjectChanges: true },
  });

  if (result.effects?.status?.status !== "success") {
    console.error("TX effects:", JSON.stringify(result.effects, null, 2));
    throw new Error("submit_proof failed: " + (result.effects?.status?.error || "unknown"));
  }

  const created = result.objectChanges?.find(
    (c) => c.type === "created" && c.objectType?.includes("VaultProof"),
  );

  if (!created || created.type !== "created") {
    throw new Error("VaultProof not found in tx result");
  }

  console.log("[OK] Proof submitted:", created.objectId);
  console.log("  TX digest:", result.digest);
  console.log("  Waiting for indexing...");
  await client.waitForTransaction({ digest: result.digest });
  return created.objectId;
}

// ====================================================================
// Step 5: Verify Proof
// ====================================================================
async function verifyProof(vaultId, proofId) {
  console.log("\n=== Step 5: Verify Proof ===");

  const tx = new Transaction();
  tx.moveCall({
    target: `${PACKAGE_ID}::abyssal_registry::verify_vault_proof`,
    arguments: [tx.object(vaultId), tx.object(proofId)],
  });

  const result = await client.devInspectTransactionBlock({
    transactionBlock: tx,
    sender: keypair.toSuiAddress(),
  });

  const retVal = result.results?.[0]?.returnValues?.[0]?.[0];
  const isValid = retVal && retVal[0] === 1;
  console.log("[OK] Proof valid:", isValid);
  return isValid;
}

// ====================================================================
// Step 6: Consume Proof (reveal result)
// ====================================================================
async function consumeProof(vaultId, proofId) {
  console.log("\n=== Step 6: Consume Proof (reveal result) ===");

  const resultValue = 650n;
  const resultSalt = 999888777666555444n;

  const resultValueBytes = bigintToBytes32LE(resultValue);
  const resultSaltBytes = bigintToBytes32LE(resultSalt);

  const tx = new Transaction();
  tx.moveCall({
    target: `${PACKAGE_ID}::abyssal_registry::consume_proof_with_result`,
    arguments: [
      tx.object(vaultId),
      tx.object(proofId),
      tx.pure.vector("u8", Array.from(resultValueBytes)),
      tx.pure.vector("u8", Array.from(resultSaltBytes)),
    ],
  });

  const result = await client.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true, showEvents: true },
  });

  if (result.effects?.status?.status !== "success") {
    console.error("TX effects:", JSON.stringify(result.effects, null, 2));
    throw new Error("consume_proof failed: " + (result.effects?.status?.error || "unknown"));
  }

  console.log("[OK] Proof consumed. Result revealed: credit_score =", Number(resultValue));
  console.log("  TX digest:", result.digest);
  if (result.events?.length) {
    console.log("  Event:", result.events[0].type);
  }
}

// ====================================================================
// Main
// ====================================================================
async function main() {
  console.log("========================================");
  console.log(" Abyssal E2E Demo - Credit Score PFE");
  console.log("========================================");

  const { vaultId, wasmDoubleHash } = await deployVault();
  await registerEnclave(vaultId, wasmDoubleHash);
  const teeResult = await generateProof(vaultId);
  const proofId = await submitProof(vaultId, teeResult);
  await verifyProof(vaultId, proofId);
  await consumeProof(vaultId, proofId);

  console.log("\n========================================");
  console.log(" E2E Demo Complete");
  console.log("========================================");
  console.log("Vault:", vaultId);
  console.log("Proof:", proofId);
  console.log("Score: 650 (revealed on-chain)");
}

main().catch((err) => {
  console.error("\n[FAIL]", err.message || err);
  process.exit(1);
});
