// Real Seal decrypt + Walrus download route for loading circuit files.
//
// Flow:
// 1. Download encrypted blobs from Walrus aggregator
// 2. Build seal_approve PTB with correct arguments
// 3. Use @mysten/seal SDK decrypt() to get plaintext
// 4. Verify wasm_double_hash integrity
// 5. Cache decrypted pk/wasm for proof generation

import { Router, type Request, type Response } from "express";
import { SealClient, SessionKey } from "@mysten/seal";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { bcs } from "@mysten/sui/bcs";
import { loadCircuit } from "../circuit.js";
import {
  getPublicKey,
  getWalletKeypair,
  getWalletPublicKeyBytes,
  signWithEphemeral,
} from "../keys.js";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { createHash } from "crypto";

const router = Router();

// Seal + Walrus configuration
const SEAL_POLICY_PACKAGE_ID =
  "0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8";

const SEAL_KEY_SERVERS = [
  {
    objectId:
      "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
    weight: 1,
  },
  {
    objectId:
      "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8",
    weight: 1,
  },
];

const WALRUS_AGGREGATOR = "https://aggregator.walrus-testnet.walrus.space";
const SUI_CLOCK = "0x0000000000000000000000000000000000000000000000000000000000000006";

// Sui client (v2 API, required by @mysten/seal)
const suiClient = new SuiJsonRpcClient({
  url: getJsonRpcFullnodeUrl("testnet"),
  network: "testnet",
});

/**
 * POST /admin/load_circuit_from_walrus
 *
 * Downloads encrypted pk/wasm from Walrus, decrypts via Seal, loads into TEE.
 *
 * Body: {
 *   vaultConfigId: string,    // On-chain VaultConfig shared object ID
 *   pkBlobId: string,         // Walrus blob ID for encrypted pk
 *   wasmBlobId: string,       // Walrus blob ID for encrypted wasm
 *   expectedWasmDoubleHash?: string  // Optional integrity check
 * }
 */
router.post("/load_circuit_from_walrus", async (req: Request, res: Response) => {
  const { vaultConfigId, pkBlobId, wasmBlobId, expectedWasmDoubleHash } =
    req.body as {
      vaultConfigId?: string;
      pkBlobId?: string;
      wasmBlobId?: string;
      expectedWasmDoubleHash?: string;
    };

  if (!vaultConfigId || !pkBlobId || !wasmBlobId) {
    res.status(400).json({
      error: "vaultConfigId, pkBlobId, and wasmBlobId are required",
    });
    return;
  }

  try {
    console.log("[seal-load] Starting Seal decrypt + Walrus download...");
    console.log(`  vaultConfigId: ${vaultConfigId}`);
    console.log(`  pkBlobId: ${pkBlobId}`);
    console.log(`  wasmBlobId: ${wasmBlobId}`);

    // Step 1: Download encrypted blobs from Walrus
    console.log("[seal-load] Downloading encrypted blobs from Walrus...");
    const encryptedPk = await downloadFromWalrus(pkBlobId);
    console.log(`  pk blob: ${encryptedPk.length} bytes`);
    const encryptedWasm = await downloadFromWalrus(wasmBlobId);
    console.log(`  wasm blob: ${encryptedWasm.length} bytes`);

    // Step 2: Build seal_approve PTB
    console.log("[seal-load] Building seal_approve PTB...");
    const txBytes = await buildSealApprovePtb(vaultConfigId);

    // Step 3: Create SessionKey with wallet signer
    console.log("[seal-load] Creating Seal SessionKey...");
    const walletKeypair = getWalletKeypair();
    const sealClient = new SealClient({
      suiClient,
      serverConfigs: SEAL_KEY_SERVERS,
      verifyKeyServers: false,
    });

    const sessionKey = await SessionKey.create({
      address: walletKeypair.toSuiAddress(),
      packageId: SEAL_POLICY_PACKAGE_ID,
      ttlMin: 10,
      signer: walletKeypair,
      suiClient,
    });

    // Step 4: Decrypt pk
    console.log("[seal-load] Decrypting pk via Seal...");
    const decryptedPk = await sealClient.decrypt({
      data: encryptedPk,
      sessionKey,
      txBytes,
    });
    console.log(`  Decrypted pk: ${decryptedPk.length} bytes`);

    // Step 5: Decrypt wasm
    console.log("[seal-load] Decrypting wasm via Seal...");
    const decryptedWasm = await sealClient.decrypt({
      data: encryptedWasm,
      sessionKey,
      txBytes,
    });
    console.log(`  Decrypted wasm: ${decryptedWasm.length} bytes`);

    // Step 6: Save decrypted files to temp directory and load
    console.log("[seal-load] Saving and loading circuit...");
    const tmpDir = "/tmp/abyssal-prover";
    mkdirSync(tmpDir, { recursive: true });
    const pkPath = `${tmpDir}/circuit.zkey`;
    const wasmPath = `${tmpDir}/circuit.wasm`;
    writeFileSync(pkPath, decryptedPk);
    writeFileSync(wasmPath, decryptedWasm);

    // Step 7: Load circuit with wasm_double_hash verification
    loadCircuit(pkPath, wasmPath, expectedWasmDoubleHash);

    console.log("[seal-load] Circuit loaded successfully from Seal + Walrus");
    res.json({
      status: "ok",
      pkSize: decryptedPk.length,
      wasmSize: decryptedWasm.length,
      wasmDoubleHash: createHash("sha256")
        .update(createHash("sha256").update(decryptedWasm).digest())
        .digest()
        .toString("hex"),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("[seal-load] Failed:", message);
    res.status(500).json({ error: message });
  }
});

/**
 * Download a blob from Walrus testnet aggregator.
 */
async function downloadFromWalrus(blobId: string): Promise<Uint8Array> {
  const url = `${WALRUS_AGGREGATOR}/v1/blobs/${blobId}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `Walrus download failed for ${blobId}: ${response.status} ${response.statusText}`,
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Build a seal_approve PTB for our abyssal_seal_policy.
 *
 * Arguments:
 * 1. id: vector<u8> = [0u8]
 * 2. vault_config: &VaultConfig (shared object)
 * 3. enclave_pubkey: vector<u8> (32 bytes)
 * 4. wallet_pubkey: vector<u8> (32 bytes)
 * 5. timestamp: u64 (ms)
 * 6. sig: vector<u8> (Ed25519 signature by ephemeral key)
 * 7. clock: &Clock (0x6)
 */
async function buildSealApprovePtb(vaultConfigId: string): Promise<Uint8Array> {
  const enclavePubkey = getPublicKey();
  const walletPubkey = getWalletPublicKeyBytes();
  const timestamp = BigInt(Date.now());

  // Build the message that seal_approve expects:
  // message = wallet_pubkey || bcs::to_bytes(&timestamp)
  const timestampBcs = bcs.u64().serialize(timestamp).toBytes();
  const message = new Uint8Array(walletPubkey.length + timestampBcs.length);
  message.set(walletPubkey, 0);
  message.set(timestampBcs, walletPubkey.length);

  // Sign with ephemeral key (not wallet!)
  const sig = signWithEphemeral(message);

  const tx = new Transaction();
  tx.moveCall({
    target: `${SEAL_POLICY_PACKAGE_ID}::abyssal_seal_policy::seal_approve`,
    arguments: [
      tx.pure.vector("u8", [0]),
      tx.object(vaultConfigId),
      tx.pure.vector("u8", Array.from(enclavePubkey)),
      tx.pure.vector("u8", Array.from(walletPubkey)),
      tx.pure.u64(timestamp),
      tx.pure.vector("u8", Array.from(sig)),
      tx.object(SUI_CLOCK),
    ],
  });

  // Build as TransactionKind only (required by Seal)
  const txBytes = await tx.build({
    client: suiClient,
    onlyTransactionKind: true,
  });

  return txBytes;
}

export default router;
