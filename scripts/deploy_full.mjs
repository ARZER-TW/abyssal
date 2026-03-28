/**
 * Full Abyssal Deployment + Audit Setup
 *
 * 1. Seal encrypt pk, wasm (VaultKeyPolicy) + circuit source (AuditAllowlistPolicy)
 * 2. Upload all 3 encrypted blobs to Walrus
 * 3. Deploy vault with 3 real blob IDs
 * 4. Create AuditAllowlist + add deployer as auditor
 * 5. Register TEE enclave
 * 6. E2E proof test (Seal decrypt from Walrus → prove → submit → verify)
 */

import { SealClient } from "@mysten/seal";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { createHash } from "crypto";
import { execSync } from "child_process";

// --- Constants ---
const ABYSSAL_PACKAGE_ID = "0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777";
const SEAL_POLICY_ID = "0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8";
const AUDIT_POLICY_ID = "0xc854ea999c3c3008e0dd978caadb6af4e5c0b8c33dc8197bce2709ed95ea00cf";
const RPC_URL = "https://fullnode.testnet.sui.io:443";
const TEE_ENDPOINT = "http://localhost:3001";

const SEAL_KEY_SERVERS = [
  { objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", weight: 1 },
  { objectId: "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8", weight: 1 },
];

const BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const client = new SuiJsonRpcClient({ url: RPC_URL, network: "testnet" });

const keystoreRaw = readFileSync(`${process.env.HOME}/.sui/sui_config/sui.keystore`, "utf8");
const keys = JSON.parse(keystoreRaw);
const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(keys[1], "base64").slice(1));
console.log("Deployer:", keypair.toSuiAddress());

// --- Format helpers ---
function bigintToBytes32LE(value) {
  const buf = Buffer.alloc(32);
  let v = BigInt(value);
  for (let i = 0; i < 32; i++) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}
function serializeG1Compressed(point) {
  const x = BigInt(point[0]), y = BigInt(point[1]);
  if (x === 0n && y === 0n) { const buf = Buffer.alloc(32); buf[31] = 0x40; return buf; }
  const xBytes = bigintToBytes32LE(x);
  if (y > BN254_P / 2n) xBytes[31] |= 0x80;
  return xBytes;
}
function serializeG2Compressed(point) {
  const xC0 = BigInt(point[0][0]), xC1 = BigInt(point[0][1]);
  const yC0 = BigInt(point[1][0]), yC1 = BigInt(point[1][1]);
  if (xC0 === 0n && xC1 === 0n && yC0 === 0n && yC1 === 0n) { const buf = Buffer.alloc(64); buf[63] = 0x40; return buf; }
  const c0Bytes = bigintToBytes32LE(xC0), c1Bytes = bigintToBytes32LE(xC1);
  const halfP = BN254_P / 2n;
  if ((yC1 !== 0n ? yC1 > halfP : yC0 > halfP)) c1Bytes[31] |= 0x80;
  const result = Buffer.alloc(64); c0Bytes.copy(result, 0); c1Bytes.copy(result, 32);
  return result;
}
function convertVK(vk) {
  const alpha = serializeG1Compressed(vk.vk_alpha_1);
  const beta = serializeG2Compressed(vk.vk_beta_2);
  const gamma = serializeG2Compressed(vk.vk_gamma_2);
  const delta = serializeG2Compressed(vk.vk_delta_2);
  const icLen = vk.IC.length;
  const icLenBuf = Buffer.alloc(8); icLenBuf.writeBigUInt64LE(BigInt(icLen));
  const icBufs = vk.IC.map(ic => serializeG1Compressed(ic));
  return Buffer.concat([alpha, beta, gamma, delta, icLenBuf, ...icBufs]);
}
function hexToBytes(hex) { return Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex"); }
function readUleb128(data, offset) {
  let result = 0, shift = 0, o = offset;
  while (true) { const byte = data[o++]; result |= (byte & 0x7f) << shift; if ((byte & 0x80) === 0) break; shift += 7; }
  return [result, o];
}
function parseBcsVecOfVecU8(data) {
  let offset = 0;
  let [outerLen, o1] = readUleb128(data, offset); offset = o1;
  const result = [];
  for (let i = 0; i < outerLen; i++) {
    let [innerLen, o2] = readUleb128(data, offset); offset = o2;
    result.push(data.slice(offset, offset + innerLen)); offset += innerLen;
  }
  return result;
}

function walrusStore(filePath) {
  const output = execSync(
    `walrus store "${filePath}" --epochs 5 --context testnet --json 2>/dev/null`,
    { encoding: "utf8", timeout: 120000 }
  );
  const raw = JSON.parse(output);
  const result = Array.isArray(raw) ? (raw[0].blobStoreResult || raw[0]) : (raw.blobStoreResult || raw);
  if (result.newlyCreated) return result.newlyCreated.blobObject.blobId;
  if (result.alreadyCertified) return result.alreadyCertified.blobId;
  throw new Error("Unexpected walrus response: " + JSON.stringify(result));
}

// ====================================================================
async function main() {
  console.log("==========================================================");
  console.log(" Abyssal Full Deploy + Audit Setup");
  console.log("==========================================================");

  const sealClient = new SealClient({
    suiClient: client,
    serverConfigs: SEAL_KEY_SERVERS,
    verifyKeyServers: false,
  });

  // --- Step 1: Read files ---
  const zkeyBytes = readFileSync("circuits/credit_score/build/credit_score_final.zkey");
  const wasmBytes = readFileSync("circuits/credit_score/build/credit_score_js/credit_score.wasm");
  const circuitSource = readFileSync("circuits/credit_score/credit_score.circom");

  console.log("\n=== Step 1: Seal Encrypt (3 blobs) ===");
  console.log(`  pk: ${zkeyBytes.length} bytes`);
  console.log(`  wasm: ${wasmBytes.length} bytes`);
  console.log(`  circuit source: ${circuitSource.length} bytes`);

  // --- Step 2: Encrypt ---
  console.log("  Encrypting pk with VaultKeyPolicy...");
  const { encryptedObject: encPk } = await sealClient.encrypt({
    threshold: 2, packageId: SEAL_POLICY_ID, id: "00",
    data: new Uint8Array(zkeyBytes),
  });

  console.log("  Encrypting wasm with VaultKeyPolicy...");
  const { encryptedObject: encWasm } = await sealClient.encrypt({
    threshold: 2, packageId: SEAL_POLICY_ID, id: "00",
    data: new Uint8Array(wasmBytes),
  });

  console.log("  Encrypting circuit source with AuditAllowlistPolicy...");
  const { encryptedObject: encSource } = await sealClient.encrypt({
    threshold: 2, packageId: AUDIT_POLICY_ID, id: "00",
    data: new Uint8Array(circuitSource),
  });

  // Save encrypted files
  mkdirSync("circuits/credit_score/build/encrypted", { recursive: true });
  writeFileSync("circuits/credit_score/build/encrypted/pk.seal", Buffer.from(encPk));
  writeFileSync("circuits/credit_score/build/encrypted/wasm.seal", Buffer.from(encWasm));
  writeFileSync("circuits/credit_score/build/encrypted/source.seal", Buffer.from(encSource));
  console.log("[OK] Seal encryption complete");

  // --- Step 3: Upload to Walrus ---
  console.log("\n=== Step 2: Walrus Upload (3 blobs) ===");
  console.log("  Uploading pk...");
  const pkBlobId = walrusStore("circuits/credit_score/build/encrypted/pk.seal");
  console.log(`  pk blob: ${pkBlobId}`);

  console.log("  Uploading wasm...");
  const wasmBlobId = walrusStore("circuits/credit_score/build/encrypted/wasm.seal");
  console.log(`  wasm blob: ${wasmBlobId}`);

  console.log("  Uploading circuit source...");
  const sourceBlobId = walrusStore("circuits/credit_score/build/encrypted/source.seal");
  console.log(`  source blob: ${sourceBlobId}`);
  console.log("[OK] Walrus upload complete");

  // --- Step 4: Deploy Vault ---
  console.log("\n=== Step 3: Deploy Vault ===");
  const vk = JSON.parse(readFileSync("circuits/credit_score/build/vk.json", "utf8"));
  const vkBytes = convertVK(vk);

  // Get pvk components via devInspect
  const inspectTx = new Transaction();
  const curve = inspectTx.moveCall({ target: "0x2::groth16::bn254" });
  const pvk = inspectTx.moveCall({
    target: "0x2::groth16::prepare_verifying_key",
    arguments: [curve[0], inspectTx.pure.vector("u8", Array.from(vkBytes))],
  });
  inspectTx.moveCall({ target: "0x2::groth16::pvk_to_bytes", arguments: [pvk[0]] });

  const inspectResult = await client.devInspectTransactionBlock({
    transactionBlock: inspectTx, sender: keypair.toSuiAddress(),
  });
  const pvkRaw = new Uint8Array(inspectResult.results[2].returnValues[0][0]);
  const components = parseBcsVecOfVecU8(pvkRaw);

  const wasmHash = createHash("sha256").update(wasmBytes).digest();
  const wasmDoubleHash = createHash("sha256").update(wasmHash).digest();

  const pkBlobBytes = Buffer.from(pkBlobId, "utf8");
  const wasmBlobBytes = Buffer.from(wasmBlobId, "utf8");
  const sourceBlobBytes = Buffer.from(sourceBlobId, "utf8");

  const tx = new Transaction();
  tx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::create_vault`,
    arguments: [
      tx.pure.vector("u8", Array.from(components[0])),
      tx.pure.vector("u8", Array.from(components[1])),
      tx.pure.vector("u8", Array.from(components[2])),
      tx.pure.vector("u8", Array.from(components[3])),
      tx.pure.vector("u8", Array.from(wasmDoubleHash)),
      tx.pure.vector("u8", Array.from(pkBlobBytes)),
      tx.pure.vector("u8", Array.from(wasmBlobBytes)),
      tx.pure.vector("u8", Array.from(sourceBlobBytes)),
      tx.pure.id(SEAL_POLICY_ID),
      tx.pure.u64(28),
      tx.pure.u8(0),
      tx.pure.vector("u8", Array.from(Buffer.from("Credit Score PFE v2 - Full Audit"))),
    ],
  });

  const deployResult = await client.signAndExecuteTransaction({
    transaction: tx, signer: keypair,
    options: { showEffects: true, showObjectChanges: true },
  });
  await client.waitForTransaction({ digest: deployResult.digest });

  const vaultObj = deployResult.objectChanges?.find(
    c => c.type === "created" && c.objectType?.includes("VaultConfig"),
  );
  if (!vaultObj || vaultObj.type !== "created") throw new Error("VaultConfig not found");
  const vaultId = vaultObj.objectId;
  console.log(`[OK] Vault: ${vaultId}`);

  // --- Step 5: Create AuditAllowlist ---
  console.log("\n=== Step 4: Create AuditAllowlist ===");
  const alTx = new Transaction();
  alTx.moveCall({
    target: `${AUDIT_POLICY_ID}::abyssal_audit_policy::create_allowlist`,
    arguments: [alTx.pure.id(vaultId)],
  });

  const alResult = await client.signAndExecuteTransaction({
    transaction: alTx, signer: keypair,
    options: { showEffects: true, showObjectChanges: true },
  });
  await client.waitForTransaction({ digest: alResult.digest });

  const allowlistObj = alResult.objectChanges?.find(
    c => c.type === "created" && c.objectType?.includes("AuditAllowlist"),
  );
  if (!allowlistObj || allowlistObj.type !== "created") throw new Error("AuditAllowlist not found");
  const allowlistId = allowlistObj.objectId;
  console.log(`  Allowlist: ${allowlistId}`);

  // Add deployer as auditor
  const addTx = new Transaction();
  addTx.moveCall({
    target: `${AUDIT_POLICY_ID}::abyssal_audit_policy::add_auditor`,
    arguments: [addTx.object(allowlistId), addTx.pure.address(keypair.toSuiAddress())],
  });
  const addResult = await client.signAndExecuteTransaction({
    transaction: addTx, signer: keypair, options: { showEffects: true },
  });
  await client.waitForTransaction({ digest: addResult.digest });
  console.log(`[OK] Deployer added as auditor`);

  // --- Step 6: Register TEE ---
  console.log("\n=== Step 5: Register TEE Enclave ===");
  const health = await fetch(`${TEE_ENDPOINT}/health`).then(r => r.json());
  const teePubkey = hexToBytes(health.pubkey);

  const regTx = new Transaction();
  regTx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::register_enclave`,
    arguments: [
      regTx.object(vaultId),
      regTx.pure.vector("u8", Array.from(teePubkey)),
      regTx.pure.vector("u8", Array.from(wasmDoubleHash)),
    ],
  });
  const regResult = await client.signAndExecuteTransaction({
    transaction: regTx, signer: keypair, options: { showEffects: true },
  });
  await client.waitForTransaction({ digest: regResult.digest });
  console.log("[OK] Enclave registered");

  // --- Step 7: Load circuit via Seal + Walrus ---
  console.log("\n=== Step 6: TEE Load Circuit (Seal + Walrus) ===");
  const loadResp = await fetch(`${TEE_ENDPOINT}/admin/load_circuit_from_walrus`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vaultConfigId: vaultId, pkBlobId, wasmBlobId }),
  });
  const loadResult = await loadResp.json();
  if (loadResult.status !== "ok") throw new Error("Load circuit failed: " + loadResult.error);
  console.log(`[OK] Circuit loaded: pk=${loadResult.pkSize}B, wasm=${loadResult.wasmSize}B`);

  // --- Step 8: E2E Proof ---
  console.log("\n=== Step 7: E2E Proof Test ===");
  const state = await client.getLatestSuiSystemState();
  const currentEpoch = Number(state.epoch);

  const vaultIdHex = vaultId.slice(2);
  const vaultIdBytes2 = Buffer.from(vaultIdHex, "hex");
  let vaultIdU256 = 0n;
  for (let i = 0; i < 32; i++) vaultIdU256 |= BigInt(vaultIdBytes2[i]) << BigInt(i * 8);
  const vaultIdField = vaultIdU256 % BN254_R;

  const income = 5000, expenses = 4800, years = 15;
  const score = 300 + (income - expenses) + years * 10;

  const proveResp = await fetch(`${TEE_ENDPOINT}/prove`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      privateInputs: {
        user_secret: "12345678901234567890",
        vault_id_field: vaultIdField.toString(),
        epoch: currentEpoch.toString(),
        result_value: score.toString(),
        result_salt: "999888777666555444",
        income: income.toString(),
        monthly_expenses: expenses.toString(),
        years_of_history: years.toString(),
      },
    }),
  });
  if (!proveResp.ok) throw new Error("TEE prove failed: " + await proveResp.text());
  const teeResult = await proveResp.json();

  const proofTx = new Transaction();
  const vaultProof = proofTx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::submit_proof`,
    arguments: [
      proofTx.object(vaultId),
      proofTx.pure.vector("u8", Array.from(hexToBytes(teeResult.pubkey_hex))),
      proofTx.pure.vector("u8", Array.from(hexToBytes(teeResult.proof_hex))),
      proofTx.pure.vector("u8", Array.from(hexToBytes(teeResult.public_inputs_hex))),
      proofTx.pure.vector("u8", Array.from(hexToBytes(teeResult.signature_hex))),
    ],
  });
  proofTx.transferObjects([vaultProof[0]], keypair.toSuiAddress());

  const proofResult = await client.signAndExecuteTransaction({
    transaction: proofTx, signer: keypair,
    options: { showEffects: true, showObjectChanges: true },
  });
  if (proofResult.effects?.status?.status !== "success") {
    throw new Error("submit_proof failed: " + (proofResult.effects?.status?.error || "unknown"));
  }

  const proofObj = proofResult.objectChanges?.find(
    c => c.type === "created" && c.objectType?.includes("VaultProof"),
  );
  console.log(`[OK] Proof: ${proofObj?.type === "created" ? proofObj.objectId : "?"}, score=${score}`);

  // --- Summary ---
  console.log("\n==========================================================");
  console.log(" Full Deploy Complete");
  console.log("==========================================================");

  const deployment = {
    vaultId,
    allowlistId,
    pkBlobId,
    wasmBlobId,
    circuitSourceBlobId: sourceBlobId,
    abyssalPackageId: ABYSSAL_PACKAGE_ID,
    sealPolicyId: SEAL_POLICY_ID,
    auditPolicyId: AUDIT_POLICY_ID,
    deployer: keypair.toSuiAddress(),
    wasmDoubleHash: wasmDoubleHash.toString("hex"),
  };

  console.log(JSON.stringify(deployment, null, 2));
  writeFileSync("scripts/deployment.json", JSON.stringify(deployment, null, 2));
  console.log("\nSaved to scripts/deployment.json");
}

main().catch(err => { console.error("\n[FAIL]", err.message || err); process.exit(1); });
