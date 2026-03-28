import { useState } from "react";
import {
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { ABYSSAL_PACKAGE_ID, SEAL_POLICY_PACKAGE_ID } from "../constants.ts";
import { serializeVkToArkworks, parseBcsVectorOfVectorU8 } from "../utils/format.ts";
import { baseStyles, colors } from "../styles.ts";

export default function DeployVault() {
  const client = useSuiClient();
  const account = useCurrentAccount();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

  const [vkJson, setVkJson] = useState("");
  const [wasmDoubleHash, setWasmDoubleHash] = useState("");
  const [sealPolicyId, setSealPolicyId] = useState(SEAL_POLICY_PACKAGE_ID);
  const [proofValidityEpochs, setProofValidityEpochs] = useState(28);
  const [nullifierPolicy, setNullifierPolicy] = useState(0);
  const [description, setDescription] = useState("");
  const [pkBlobId, setPkBlobId] = useState("");
  const [wasmBlobId, setWasmBlobId] = useState("");

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleDeploy() {
    if (!account) {
      setError("Please connect your wallet first.");
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      // 1. Parse VK JSON and serialize to Arkworks format
      const vk = JSON.parse(vkJson);
      const vkBytes = serializeVkToArkworks(vk);

      // 2. Call prepare_verifying_key via devInspect to get 4 pvk components
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
        sender: account.address,
      });

      if (!inspectResult.results?.[2]?.returnValues) {
        throw new Error("devInspect failed: no return values from pvk_to_bytes");
      }

      const rawBytes = new Uint8Array(
        inspectResult.results[2].returnValues[0][0] as number[],
      );
      const [vkGammaAbcG1, alphaBetaPairing, gammaG2NegPc, deltaG2NegPc] =
        parseBcsVectorOfVectorU8(rawBytes);

      // 3. Build create_vault PTB
      const wasmHashBytes = hexToBytes(wasmDoubleHash);
      const pkBlobBytes = pkBlobId ? hexToBytes(pkBlobId) : new Uint8Array([0]);
      const wasmBlobBytes = wasmBlobId ? hexToBytes(wasmBlobId) : new Uint8Array([0]);

      const tx = new Transaction();
      const vaultId = tx.moveCall({
        target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::create_vault`,
        arguments: [
          tx.pure.vector("u8", Array.from(vkGammaAbcG1)),
          tx.pure.vector("u8", Array.from(alphaBetaPairing)),
          tx.pure.vector("u8", Array.from(gammaG2NegPc)),
          tx.pure.vector("u8", Array.from(deltaG2NegPc)),
          tx.pure.vector("u8", Array.from(wasmHashBytes)),
          tx.pure.vector("u8", Array.from(pkBlobBytes)),
          tx.pure.vector("u8", Array.from(wasmBlobBytes)),
          tx.pure.id(sealPolicyId),
          tx.pure.u64(proofValidityEpochs),
          tx.pure.u8(nullifierPolicy),
          tx.pure.vector(
            "u8",
            Array.from(new TextEncoder().encode(description)),
          ),
        ],
      });
      // create_vault returns ID but shares the object, nothing to transfer
      void vaultId;

      const txResult = await signAndExecute({
        transaction: tx,
      });

      // Wait for transaction to be indexed
      const response = await client.waitForTransaction({
        digest: txResult.digest,
        options: { showObjectChanges: true },
      });

      const created = response.objectChanges?.find(
        (c) => c.type === "created" && c.objectType?.includes("VaultConfig"),
      );

      if (created && created.type === "created") {
        setResult(created.objectId);
      } else {
        setResult(`Transaction succeeded: ${txResult.digest}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={baseStyles.page}>
      <h2 style={baseStyles.h2}>Deploy Vault</h2>
      <div style={baseStyles.card}>
        <div style={baseStyles.field}>
          <label style={baseStyles.label}>VK JSON (paste verification_key.json content)</label>
          <textarea
            style={baseStyles.textarea}
            value={vkJson}
            onChange={(e) => setVkJson(e.target.value)}
            placeholder='{"vk_alpha_1": [...], "vk_beta_2": [...], ...}'
          />
        </div>

        <div style={baseStyles.field}>
          <label style={baseStyles.label}>Wasm Double Hash (hex, 32 bytes)</label>
          <input
            style={baseStyles.input}
            value={wasmDoubleHash}
            onChange={(e) => setWasmDoubleHash(e.target.value)}
            placeholder="0xabcd..."
          />
        </div>

        <div style={baseStyles.field}>
          <label style={baseStyles.label}>Seal Policy ID</label>
          <input
            style={baseStyles.input}
            value={sealPolicyId}
            onChange={(e) => setSealPolicyId(e.target.value)}
          />
        </div>

        <div style={{ display: "flex", gap: "16px" }}>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>Proof Validity (epochs)</label>
            <input
              style={baseStyles.input}
              type="number"
              value={proofValidityEpochs}
              onChange={(e) => setProofValidityEpochs(Number(e.target.value))}
            />
          </div>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>Nullifier Policy</label>
            <select
              style={baseStyles.select}
              value={nullifierPolicy}
              onChange={(e) => setNullifierPolicy(Number(e.target.value))}
            >
              <option value={0}>One-time (0)</option>
              <option value={1}>Once-per-epoch (1)</option>
              <option value={2}>Unlimited (2)</option>
            </select>
          </div>
        </div>

        <div style={baseStyles.field}>
          <label style={baseStyles.label}>PK Blob ID (hex, optional)</label>
          <input
            style={baseStyles.input}
            value={pkBlobId}
            onChange={(e) => setPkBlobId(e.target.value)}
            placeholder="Walrus blob ID (hex)"
          />
        </div>

        <div style={baseStyles.field}>
          <label style={baseStyles.label}>Wasm Blob ID (hex, optional)</label>
          <input
            style={baseStyles.input}
            value={wasmBlobId}
            onChange={(e) => setWasmBlobId(e.target.value)}
            placeholder="Walrus blob ID (hex)"
          />
        </div>

        <div style={baseStyles.field}>
          <label style={baseStyles.label}>Description</label>
          <input
            style={baseStyles.input}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Credit score vault v1"
          />
        </div>

        <button
          style={{
            ...baseStyles.button,
            ...(loading || !account ? baseStyles.buttonDisabled : {}),
          }}
          onClick={handleDeploy}
          disabled={loading || !account}
        >
          {loading ? "Deploying..." : "Deploy Vault"}
        </button>

        {!account && (
          <p style={{ color: colors.warning, fontSize: "13px", marginTop: "12px" }}>
            Connect wallet to deploy.
          </p>
        )}

        {result && (
          <div style={{ ...baseStyles.resultBox, ...baseStyles.successBox }}>
            <strong>Vault Created</strong>
            <br />
            {result}
          </div>
        )}

        {error && (
          <div style={{ ...baseStyles.resultBox, ...baseStyles.errorBox }}>
            <strong>Error</strong>
            <br />
            {error}
          </div>
        )}
      </div>
    </div>
  );
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
