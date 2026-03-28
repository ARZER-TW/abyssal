import { SuiClient } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { computePvkComponents } from "./pvk.js";
import { computeCircuitHashes } from "./hashes.js";
import type { VaultDeployParams } from "./types.js";

/** Testnet package IDs */
const ABYSSAL_PACKAGE_ID =
  "0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777";

/**
 * Deploy a new Abyssal vault on-chain.
 *
 * 1. Converts VK to Arkworks format (raw VK bytes)
 * 2. Calls prepare_verifying_key on-chain to get 4 pvk components
 * 3. Calls create_vault with the components
 *
 * For hackathon: uses prepare_verifying_key on-chain (higher gas, simpler).
 * Production: pre-compute pvk components off-chain via dry-run.
 *
 * @returns The created vault's object ID
 */
export async function deployVault(
  params: VaultDeployParams,
  signer: Ed25519Keypair,
  rpcUrl: string,
): Promise<string> {
  const client = new SuiClient({ url: rpcUrl });

  const { vkBytes } = await computePvkComponents(params.vkJsonPath);
  const { wasmDoubleHash } = await computeCircuitHashes(params.wasmPath);

  const tx = new Transaction();

  // Step 1: prepare_verifying_key on-chain to get PreparedVerifyingKey
  const [pvk] = tx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::create_vault_with_raw_vk`,
    arguments: [
      tx.pure.vector("u8", Array.from(vkBytes)),
      tx.pure.vector("u8", Array.from(wasmDoubleHash)),
      tx.pure.vector("u8", Array.from(hexToBytes(params.sealPolicyId))),
      tx.pure.u64(params.proofValidityEpochs),
      tx.pure.u8(params.nullifierPolicy),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(params.description))),
    ],
  });

  // Note: The current contract uses pvk_from_bytes with 4 separate args.
  // For hackathon, we'll build a PTB that calls prepare_verifying_key first,
  // then passes the 4 components to create_vault.

  // Actually, let's build the PTB properly:
  const txb = new Transaction();

  // Call groth16::prepare_verifying_key to get pvk
  const curve = txb.moveCall({
    target: "0x2::groth16::bn254",
  });

  const preparedPvk = txb.moveCall({
    target: "0x2::groth16::prepare_verifying_key",
    arguments: [curve[0], txb.pure.vector("u8", Array.from(vkBytes))],
  });

  // Extract 4 components via pvk_to_bytes
  const pvkBytesVec = txb.moveCall({
    target: "0x2::groth16::pvk_to_bytes",
    arguments: [preparedPvk[0]],
  });

  // Now call create_vault with the 4 components
  // Problem: pvk_to_bytes returns vector<vector<u8>> but we need individual vectors.
  // In PTB, we can't easily index into a vector result.
  // Workaround: pass the raw VK and let the contract handle it.

  // For now, use a simpler approach: pre-compute pvk components via dry-run,
  // then pass them directly.

  const pvkComponents = await getPvkComponentsViaDryRun(client, vkBytes);

  const tx2 = new Transaction();
  const vaultId = tx2.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::create_vault`,
    arguments: [
      tx2.pure.vector("u8", Array.from(pvkComponents[0])),
      tx2.pure.vector("u8", Array.from(pvkComponents[1])),
      tx2.pure.vector("u8", Array.from(pvkComponents[2])),
      tx2.pure.vector("u8", Array.from(pvkComponents[3])),
      tx2.pure.vector("u8", Array.from(wasmDoubleHash)),
      tx2.pure.vector("u8", [0x12, 0x34]), // dummy pk_blob_id
      tx2.pure.vector("u8", [0x56, 0x78]), // dummy wasm_blob_id
      tx2.pure.vector("u8", []),            // circuit_source_blob_id (set by deploy script)
      tx2.pure.id(params.sealPolicyId),
      tx2.pure.u64(params.proofValidityEpochs),
      tx2.pure.u8(params.nullifierPolicy),
      tx2.pure.vector("u8", Array.from(new TextEncoder().encode(params.description))),
    ],
  });

  const result = await client.signAndExecuteTransaction({
    transaction: tx2,
    signer,
    options: { showEffects: true, showObjectChanges: true },
  });

  const created = result.objectChanges?.find(
    (c) => c.type === "created" && c.objectType?.includes("VaultConfig"),
  );

  if (!created || created.type !== "created") {
    throw new Error("VaultConfig object not found in transaction results");
  }

  return created.objectId;
}

/**
 * Register a TEE enclave public key for an existing vault.
 * Only the vault owner can call this.
 */
export async function registerEnclaveForVault(
  vaultId: string,
  enclavePubkey: Uint8Array,
  wasmDoubleHash: Uint8Array,
  signer: Ed25519Keypair,
  rpcUrl: string,
): Promise<void> {
  const client = new SuiClient({ url: rpcUrl });

  const tx = new Transaction();
  tx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::register_enclave`,
    arguments: [
      tx.object(vaultId),
      tx.pure.vector("u8", Array.from(enclavePubkey)),
      tx.pure.vector("u8", Array.from(wasmDoubleHash)),
    ],
  });

  await client.signAndExecuteTransaction({
    transaction: tx,
    signer,
    options: { showEffects: true },
  });
}

/**
 * Get pvk components by calling prepare_verifying_key via dev-inspect (dry-run).
 * Returns the 4 byte arrays from pvk_to_bytes.
 */
async function getPvkComponentsViaDryRun(
  client: SuiClient,
  vkBytes: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array, Uint8Array]> {
  const tx = new Transaction();

  const curve = tx.moveCall({ target: "0x2::groth16::bn254" });
  const pvk = tx.moveCall({
    target: "0x2::groth16::prepare_verifying_key",
    arguments: [curve[0], tx.pure.vector("u8", Array.from(vkBytes))],
  });
  const components = tx.moveCall({
    target: "0x2::groth16::pvk_to_bytes",
    arguments: [pvk[0]],
  });

  const result = await client.devInspectTransactionBlock({
    transactionBlock: tx,
    sender: "0x0000000000000000000000000000000000000000000000000000000000000000",
  });

  if (result.results?.[2]?.returnValues) {
    const returnValues = result.results[2].returnValues;
    // pvk_to_bytes returns vector<vector<u8>>
    // The BCS encoding is: length(u32) then each inner vector (length + bytes)
    const raw = new Uint8Array(returnValues[0][0] as number[]);
    return parseBcsVectorOfVectorU8(raw);
  }

  throw new Error("Failed to get PVK components via dev-inspect");
}

function parseBcsVectorOfVectorU8(
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

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
