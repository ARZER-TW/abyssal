import { useState } from "react";
import {
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { ABYSSAL_PACKAGE_ID, TEE_ENDPOINT, BN254_R } from "../constants.ts";
import { bigintToBytes32LE } from "../utils/format.ts";
import { bytesToHex } from "../utils/hex.ts";
import { baseStyles, colors } from "../styles.ts";

export default function GenerateProof() {
  const client = useSuiClient();
  const account = useCurrentAccount();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

  const [vaultId, setVaultId] = useState("");
  const [income, setIncome] = useState(5000);
  const [expenses, setExpenses] = useState(2000);
  const [years, setYears] = useState(3);
  const [userSecret, setUserSecret] = useState("");
  const [resultSalt, setResultSalt] = useState("");
  const [teeEndpoint, setTeeEndpoint] = useState(TEE_ENDPOINT);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    proofId: string;
    score: number;
    digest: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleGenerate() {
    if (!account) {
      setError("Please connect your wallet first.");
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      // Compute vault_id_field = BigInt(vaultId) % BN254_R
      const vaultIdBigint = BigInt(vaultId);
      const vaultIdField = vaultIdBigint % BN254_R;

      // Get current epoch
      const latestCheckpoint = await client.getLatestCheckpointSequenceNumber();
      const checkpoint = await client.getCheckpoint({ id: latestCheckpoint });
      const currentEpoch = Number(checkpoint.epoch);

      // Compute result_value (credit score formula)
      const resultValue = 300 + (income - expenses) + years * 10;

      // Build input object for TEE
      const proveInput = {
        vault_id: vaultId,
        private_inputs: {
          income: String(income),
          monthly_expenses: String(expenses),
          years_of_history: String(years),
          user_secret: userSecret || "12345",
          result_salt: resultSalt || "67890",
          vault_id_field: String(vaultIdField),
          current_epoch: String(currentEpoch),
          proof_validity_epochs: "28",
        },
      };

      // POST to TEE /prove endpoint
      const teeResponse = await fetch(`${teeEndpoint}/prove`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(proveInput),
      });

      if (!teeResponse.ok) {
        const body = await teeResponse.text();
        throw new Error(`TEE /prove failed (${teeResponse.status}): ${body}`);
      }

      const teeResult = (await teeResponse.json()) as {
        proof_hex: string;
        public_inputs_hex: string;
        signature_hex: string;
        pubkey_hex: string;
      };

      const proofBytes = hexToBytes(teeResult.proof_hex);
      const publicInputsBytes = hexToBytes(teeResult.public_inputs_hex);
      const signature = hexToBytes(teeResult.signature_hex);
      const enclavePubkey = hexToBytes(teeResult.pubkey_hex);

      // Build submit_proof PTB
      const tx = new Transaction();
      const vaultProof = tx.moveCall({
        target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::submit_proof`,
        arguments: [
          tx.object(vaultId),
          tx.pure.vector("u8", Array.from(enclavePubkey)),
          tx.pure.vector("u8", Array.from(proofBytes)),
          tx.pure.vector("u8", Array.from(publicInputsBytes)),
          tx.pure.vector("u8", Array.from(signature)),
        ],
      });

      // Transfer the VaultProof to the caller
      tx.transferObjects([vaultProof[0]], account.address);

      const txResult = await signAndExecute({
        transaction: tx,
      });

      const response = await client.waitForTransaction({
        digest: txResult.digest,
        options: { showObjectChanges: true },
      });

      const created = response.objectChanges?.find(
        (c) => c.type === "created" && c.objectType?.includes("VaultProof"),
      );

      const proofId =
        created && created.type === "created"
          ? created.objectId
          : "Unknown (check digest)";

      setResult({
        proofId,
        score: resultValue,
        digest: txResult.digest,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  // Suppress unused import warning - bigintToBytes32LE and bytesToHex are available for future use
  void bigintToBytes32LE;
  void bytesToHex;

  return (
    <div style={baseStyles.page}>
      <h2 style={baseStyles.h2}>Generate Proof</h2>
      <div style={baseStyles.card}>
        <div style={baseStyles.field}>
          <label style={baseStyles.label}>Vault ID</label>
          <input
            style={baseStyles.input}
            value={vaultId}
            onChange={(e) => setVaultId(e.target.value)}
            placeholder="0x..."
          />
        </div>

        <div style={{ display: "flex", gap: "16px" }}>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>Income</label>
            <input
              style={baseStyles.input}
              type="number"
              value={income}
              onChange={(e) => setIncome(Number(e.target.value))}
            />
          </div>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>Monthly Expenses</label>
            <input
              style={baseStyles.input}
              type="number"
              value={expenses}
              onChange={(e) => setExpenses(Number(e.target.value))}
            />
          </div>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>Years of History</label>
            <input
              style={baseStyles.input}
              type="number"
              value={years}
              onChange={(e) => setYears(Number(e.target.value))}
            />
          </div>
        </div>

        <div style={{ display: "flex", gap: "16px" }}>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>User Secret (for nullifier)</label>
            <input
              style={baseStyles.input}
              value={userSecret}
              onChange={(e) => setUserSecret(e.target.value)}
              placeholder="e.g. 12345"
            />
          </div>
          <div style={{ ...baseStyles.field, flex: 1 }}>
            <label style={baseStyles.label}>Result Salt (for commitment)</label>
            <input
              style={baseStyles.input}
              value={resultSalt}
              onChange={(e) => setResultSalt(e.target.value)}
              placeholder="e.g. 67890"
            />
          </div>
        </div>

        <div style={baseStyles.field}>
          <label style={baseStyles.label}>TEE Endpoint</label>
          <input
            style={baseStyles.input}
            value={teeEndpoint}
            onChange={(e) => setTeeEndpoint(e.target.value)}
          />
        </div>

        <div
          style={{
            ...baseStyles.resultBox,
            ...baseStyles.infoBox,
            marginTop: 0,
            marginBottom: "16px",
          }}
        >
          <strong>Estimated Score:</strong>{" "}
          {300 + (income - expenses) + years * 10}
          <br />
          <span style={{ color: colors.textMuted, fontSize: "12px" }}>
            Formula: 300 + (income - expenses) + years * 10
          </span>
        </div>

        <button
          style={{
            ...baseStyles.button,
            ...(loading || !account ? baseStyles.buttonDisabled : {}),
          }}
          onClick={handleGenerate}
          disabled={loading || !account}
        >
          {loading ? "Generating..." : "Generate Proof via TEE"}
        </button>

        {!account && (
          <p style={{ color: colors.warning, fontSize: "13px", marginTop: "12px" }}>
            Connect wallet to generate proof.
          </p>
        )}

        {result && (
          <div style={{ ...baseStyles.resultBox, ...baseStyles.successBox }}>
            <strong>Proof Submitted</strong>
            <br />
            VaultProof ID: {result.proofId}
            <br />
            Score: {result.score}
            <br />
            Digest: {result.digest}
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
