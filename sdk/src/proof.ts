import { SuiClient } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import type { ProveRequest, ProveResponse } from "./types.js";

const ABYSSAL_PACKAGE_ID =
  "0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777";

/**
 * Generate a ZK proof via the TEE enclave and submit it on-chain.
 *
 * 1. Sends private inputs to the TEE /prove endpoint
 * 2. Receives Groth16 proof + Ed25519 signature
 * 3. Submits a transaction calling submit_proof on-chain
 *
 * @returns The on-chain VaultProof object ID
 */
export async function generateAndSubmitProof(
  request: ProveRequest,
  teeEndpoint: string,
  signer: Ed25519Keypair,
  rpcUrl: string,
): Promise<string> {
  const client = new SuiClient({ url: rpcUrl });

  // Step 1: Call TEE /prove
  const teeResponse = await fetch(`${teeEndpoint}/prove`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ privateInputs: request.privateInputs }),
  });

  if (!teeResponse.ok) {
    throw new Error(`TEE /prove failed: ${teeResponse.status} ${await teeResponse.text()}`);
  }

  const teeResult = await teeResponse.json() as {
    proof_hex: string;
    public_inputs_hex: string;
    signature_hex: string;
    pubkey_hex: string;
  };

  const proofBytes = hexToBytes(teeResult.proof_hex);
  const publicInputsBytes = hexToBytes(teeResult.public_inputs_hex);
  const signature = hexToBytes(teeResult.signature_hex);
  const enclavePubkey = hexToBytes(teeResult.pubkey_hex);

  // Step 2: Build submit_proof PTB
  const tx = new Transaction();
  const vaultProof = tx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::submit_proof`,
    arguments: [
      tx.object(request.vaultId),
      tx.pure.vector("u8", Array.from(enclavePubkey)),
      tx.pure.vector("u8", Array.from(proofBytes)),
      tx.pure.vector("u8", Array.from(publicInputsBytes)),
      tx.pure.vector("u8", Array.from(signature)),
    ],
  });

  // Transfer VaultProof to the caller
  tx.transferObjects([vaultProof[0]], signer.toSuiAddress());

  const result = await client.signAndExecuteTransaction({
    transaction: tx,
    signer,
    options: { showEffects: true, showObjectChanges: true },
  });

  const created = result.objectChanges?.find(
    (c) => c.type === "created" && c.objectType?.includes("VaultProof"),
  );

  if (!created || created.type !== "created") {
    throw new Error("VaultProof object not found in transaction results");
  }

  return created.objectId;
}

/**
 * Verify an existing on-chain VaultProof (non-consuming).
 *
 * Calls verify_vault_proof which checks vault_id match and epoch validity.
 *
 * @returns true if proof is still valid
 */
export async function verifyVaultProof(
  vaultId: string,
  proofId: string,
  rpcUrl: string,
): Promise<boolean> {
  const client = new SuiClient({ url: rpcUrl });

  const tx = new Transaction();
  tx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::verify_vault_proof`,
    arguments: [tx.object(vaultId), tx.object(proofId)],
  });

  const result = await client.devInspectTransactionBlock({
    transactionBlock: tx,
    sender: "0x0000000000000000000000000000000000000000000000000000000000000000",
  });

  if (result.results?.[0]?.returnValues) {
    const raw = result.results[0].returnValues[0][0] as number[];
    return raw[0] === 1;
  }

  return false;
}

/**
 * Consume a VaultProof by revealing the result.
 *
 * This destroys the VaultProof object and emits a ProofConsumed event.
 *
 * @param resultValueBytes - 32-byte LE result value
 * @param resultSaltBytes - 32-byte LE result salt
 */
export async function consumeProofWithResult(
  vaultId: string,
  proofId: string,
  resultValueBytes: Uint8Array,
  resultSaltBytes: Uint8Array,
  signer: Ed25519Keypair,
  rpcUrl: string,
): Promise<void> {
  const client = new SuiClient({ url: rpcUrl });

  const tx = new Transaction();
  tx.moveCall({
    target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::consume_proof_with_result`,
    arguments: [
      tx.object(vaultId),
      tx.object(proofId),
      tx.pure.vector("u8", Array.from(resultValueBytes)),
      tx.pure.vector("u8", Array.from(resultSaltBytes)),
    ],
  });

  await client.signAndExecuteTransaction({
    transaction: tx,
    signer,
    options: { showEffects: true },
  });
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
