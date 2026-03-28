import { useState } from "react";
import {
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { ABYSSAL_PACKAGE_ID } from "../constants.ts";
import { bigintToBytes32LE } from "../utils/format.ts";
import { baseStyles, colors } from "../styles.ts";

export default function VerifyConsume() {
  return (
    <div style={baseStyles.page}>
      <h2 style={baseStyles.h2}>Verify / Consume Proof</h2>
      <VerifySection />
      <ConsumeSection />
    </div>
  );
}

function VerifySection() {
  const client = useSuiClient();

  const [vaultId, setVaultId] = useState("");
  const [proofId, setProofId] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleVerify() {
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const tx = new Transaction();
      tx.moveCall({
        target: `${ABYSSAL_PACKAGE_ID}::abyssal_registry::verify_vault_proof`,
        arguments: [tx.object(vaultId), tx.object(proofId)],
      });

      const inspectResult = await client.devInspectTransactionBlock({
        transactionBlock: tx,
        sender:
          "0x0000000000000000000000000000000000000000000000000000000000000000",
      });

      if (inspectResult.results?.[0]?.returnValues) {
        const raw = inspectResult.results[0].returnValues[0][0] as number[];
        const isValid = raw[0] === 1;
        setResult(isValid ? "VALID" : "INVALID / EXPIRED");
      } else if (inspectResult.error) {
        setResult(`INVALID: ${inspectResult.error}`);
      } else {
        setResult("INVALID: No return value");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={baseStyles.card}>
      <h3 style={baseStyles.h3}>Verify Proof (non-consuming)</h3>

      <div style={baseStyles.field}>
        <label style={baseStyles.label}>Vault ID</label>
        <input
          style={baseStyles.input}
          value={vaultId}
          onChange={(e) => setVaultId(e.target.value)}
          placeholder="0x..."
        />
      </div>

      <div style={baseStyles.field}>
        <label style={baseStyles.label}>Proof ID</label>
        <input
          style={baseStyles.input}
          value={proofId}
          onChange={(e) => setProofId(e.target.value)}
          placeholder="0x..."
        />
      </div>

      <button
        style={{
          ...baseStyles.button,
          ...(loading ? baseStyles.buttonDisabled : {}),
        }}
        onClick={handleVerify}
        disabled={loading}
      >
        {loading ? "Verifying..." : "Verify"}
      </button>

      {result && (
        <div
          style={{
            ...baseStyles.resultBox,
            ...(result === "VALID" ? baseStyles.successBox : baseStyles.errorBox),
          }}
        >
          <strong>Result:</strong> {result}
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
  );
}

function ConsumeSection() {
  const client = useSuiClient();
  const account = useCurrentAccount();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

  const [vaultId, setVaultId] = useState("");
  const [proofId, setProofId] = useState("");
  const [resultValue, setResultValue] = useState("");
  const [resultSaltInput, setResultSaltInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleConsume() {
    if (!account) {
      setError("Please connect your wallet first.");
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const resultValueBytes = bigintToBytes32LE(BigInt(resultValue));
      const resultSaltBytes = bigintToBytes32LE(BigInt(resultSaltInput));

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

      const txResult = await signAndExecute({
        transaction: tx,
      });

      await client.waitForTransaction({ digest: txResult.digest });

      setResult(`Proof consumed. Transaction: ${txResult.digest}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={baseStyles.card}>
      <h3 style={baseStyles.h3}>Consume Proof (reveals result, destroys proof)</h3>

      <div style={baseStyles.field}>
        <label style={baseStyles.label}>Vault ID</label>
        <input
          style={baseStyles.input}
          value={vaultId}
          onChange={(e) => setVaultId(e.target.value)}
          placeholder="0x..."
        />
      </div>

      <div style={baseStyles.field}>
        <label style={baseStyles.label}>Proof ID</label>
        <input
          style={baseStyles.input}
          value={proofId}
          onChange={(e) => setProofId(e.target.value)}
          placeholder="0x..."
        />
      </div>

      <div style={{ display: "flex", gap: "16px" }}>
        <div style={{ ...baseStyles.field, flex: 1 }}>
          <label style={baseStyles.label}>Result Value (integer)</label>
          <input
            style={baseStyles.input}
            value={resultValue}
            onChange={(e) => setResultValue(e.target.value)}
            placeholder="e.g. 3330"
          />
        </div>
        <div style={{ ...baseStyles.field, flex: 1 }}>
          <label style={baseStyles.label}>Result Salt (integer)</label>
          <input
            style={baseStyles.input}
            value={resultSaltInput}
            onChange={(e) => setResultSaltInput(e.target.value)}
            placeholder="e.g. 67890"
          />
        </div>
      </div>

      <button
        style={{
          ...baseStyles.button,
          ...(loading || !account ? baseStyles.buttonDisabled : {}),
        }}
        onClick={handleConsume}
        disabled={loading || !account}
      >
        {loading ? "Consuming..." : "Consume Proof"}
      </button>

      {!account && (
        <p style={{ color: colors.warning, fontSize: "13px", marginTop: "12px" }}>
          Connect wallet to consume.
        </p>
      )}

      {result && (
        <div style={{ ...baseStyles.resultBox, ...baseStyles.successBox }}>
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
  );
}
