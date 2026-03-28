/**
 * Abyssal Audit Script — Layer 1+2 of Five-Layer Verification Chain
 *
 * Layer 1: Decrypt circuit source from Seal (AuditAllowlistPolicy)
 * Layer 2: Compile → compute wasm_double_hash → compare with on-chain
 *
 * Requires: auditor address must be in AuditAllowlist
 */

import { SealClient, SessionKey } from "@mysten/seal";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { createHash } from "crypto";
import { execSync } from "child_process";

// Load deployment info
const deployment = JSON.parse(readFileSync("scripts/deployment.json", "utf8"));
const {
  vaultId,
  allowlistId,
  circuitSourceBlobId,
  auditPolicyId,
  abyssalPackageId,
  wasmDoubleHash: expectedWasmDoubleHash,
} = deployment;

const WALRUS_AGGREGATOR = "https://aggregator.walrus-testnet.walrus.space";
const SUI_CLOCK = "0x0000000000000000000000000000000000000000000000000000000000000006";

const SEAL_KEY_SERVERS = [
  { objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", weight: 1 },
  { objectId: "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8", weight: 1 },
];

const client = new SuiJsonRpcClient({
  url: getJsonRpcFullnodeUrl("testnet"),
  network: "testnet",
});

// Auditor keypair (in real scenario, auditor uses their own wallet)
// For this demo, deployer = auditor
const keystoreRaw = readFileSync(`${process.env.HOME}/.sui/sui_config/sui.keystore`, "utf8");
const keys = JSON.parse(keystoreRaw);
const auditorKeypair = Ed25519Keypair.fromSecretKey(Buffer.from(keys[1], "base64").slice(1));

console.log("==========================================================");
console.log(" Abyssal Vault Audit — Layer 1+2 Verification");
console.log("==========================================================");
console.log(`Auditor:   ${auditorKeypair.toSuiAddress()}`);
console.log(`Vault:     ${vaultId}`);
console.log(`Allowlist: ${allowlistId}`);
console.log(`Source blob: ${circuitSourceBlobId}`);

// ====================================================================
// Layer 1: Decrypt circuit source from Seal
// ====================================================================
console.log("\n=== Layer 1: Decrypt Circuit Source ===");

// Step 1: Download encrypted source from Walrus
console.log("  Downloading encrypted source from Walrus...");
const encryptedResp = await fetch(`${WALRUS_AGGREGATOR}/v1/blobs/${circuitSourceBlobId}`);
if (!encryptedResp.ok) throw new Error(`Walrus download failed: ${encryptedResp.status}`);
const encryptedSource = new Uint8Array(await encryptedResp.arrayBuffer());
console.log(`  Encrypted source: ${encryptedSource.length} bytes`);

// Step 2: Build audit seal_approve PTB
console.log("  Building audit seal_approve PTB...");
const tx = new Transaction();
tx.moveCall({
  target: `${auditPolicyId}::abyssal_audit_policy::seal_approve`,
  arguments: [
    tx.pure.vector("u8", [0]),    // id = [0u8]
    tx.object(allowlistId),        // &AuditAllowlist
    tx.object(SUI_CLOCK),          // &Clock
  ],
});
const txBytes = await tx.build({ client, onlyTransactionKind: true });

// Step 3: Create SessionKey + Seal decrypt
console.log("  Creating Seal SessionKey...");
const sealClient = new SealClient({
  suiClient: client,
  serverConfigs: SEAL_KEY_SERVERS,
  verifyKeyServers: false,
});

const sessionKey = await SessionKey.create({
  address: auditorKeypair.toSuiAddress(),
  packageId: auditPolicyId,
  ttlMin: 10,
  signer: auditorKeypair,
  suiClient: client,
});

console.log("  Decrypting via Seal key servers...");
const decryptedSource = await sealClient.decrypt({
  data: encryptedSource,
  sessionKey,
  txBytes,
});

const sourceText = new TextDecoder().decode(decryptedSource);
console.log(`  Decrypted source: ${decryptedSource.length} bytes`);
console.log(`  First line: ${sourceText.split("\n")[0]}`);

// Save decrypted source
mkdirSync("scripts/audit_output", { recursive: true });
writeFileSync("scripts/audit_output/circuit_source.circom", sourceText);
console.log("[OK] Layer 1: Circuit source decrypted and saved");

// ====================================================================
// Layer 2: Compile + verify wasm_double_hash
// ====================================================================
console.log("\n=== Layer 2: Verify wasm_double_hash ===");

// Step 1: Compile the decrypted circuit
console.log("  Compiling circuit...");
try {
  execSync(
    `circom scripts/audit_output/circuit_source.circom --wasm -l circuits/node_modules -o scripts/audit_output 2>&1`,
    { encoding: "utf8", timeout: 60000 }
  );
} catch (e) {
  console.log("  Compile output:", e.stdout || e.message);
}

// Step 2: Compute wasm_double_hash
const compiledWasmPath = "scripts/audit_output/circuit_source_js/circuit_source.wasm";
const compiledWasm = readFileSync(compiledWasmPath);
const wasmHash = createHash("sha256").update(compiledWasm).digest();
const computedDoubleHash = createHash("sha256").update(wasmHash).digest().toString("hex");

console.log(`  Computed wasm_double_hash: ${computedDoubleHash}`);
console.log(`  On-chain wasm_double_hash: ${expectedWasmDoubleHash}`);

const hashMatch = computedDoubleHash === expectedWasmDoubleHash;
console.log(`  Match: ${hashMatch ? "YES" : "NO"}`);

if (hashMatch) {
  console.log("[OK] Layer 2: Circuit source matches on-chain wasm_double_hash");
} else {
  console.log("[FAIL] Layer 2: MISMATCH! On-chain vault uses a different circuit!");
}

// ====================================================================
// Audit Report
// ====================================================================
console.log("\n=== Audit Report ===");

const report = {
  timestamp: new Date().toISOString(),
  auditor: auditorKeypair.toSuiAddress(),
  vaultId,
  allowlistId,
  circuitSourceBlobId,

  layer1: {
    status: "PASS",
    description: "Circuit source decrypted from Seal via AuditAllowlistPolicy",
    sourceSize: decryptedSource.length,
    sourcePath: "scripts/audit_output/circuit_source.circom",
  },

  layer2: {
    status: hashMatch ? "PASS" : "FAIL",
    description: "wasm_double_hash comparison",
    computedHash: computedDoubleHash,
    onChainHash: expectedWasmDoubleHash,
    match: hashMatch,
  },

  layer3: { status: "SKIP", description: "Requires Nautilus TEE attestation (R4)" },
  layer4: { status: "SKIP", description: "Requires Nautilus PCR verification (R4)" },
  layer5: { status: "PARTIAL", description: "Trusted Setup: deployer + beacon only" },

  circuitAnalysis: {
    firstLine: sourceText.split("\n")[0],
    lineCount: sourceText.split("\n").length,
    hasVECSOutputs: sourceText.includes("signal output nullifier") &&
                    sourceText.includes("signal output result_commitment") &&
                    sourceText.includes("signal output vault_id_hash") &&
                    sourceText.includes("signal output expiry_epoch"),
  },
};

writeFileSync("scripts/audit_output/audit_report.json", JSON.stringify(report, null, 2));

console.log(JSON.stringify(report, null, 2));
console.log("\nSaved to scripts/audit_output/audit_report.json");
