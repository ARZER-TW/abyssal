import { useState } from "react";
import { useSuiClient } from "@mysten/dapp-kit";
import { baseStyles, colors } from "../styles.ts";

interface VaultDetails {
  id: string;
  owner: string;
  paused: boolean;
  proofValidityEpochs: string;
  nullifierPolicy: string;
  description: string;
  enclaveCount: number;
  sealPolicyId: string;
  wasmDoubleHash: string;
}

export default function BrowseVaults() {
  const client = useSuiClient();

  const [vaultId, setVaultId] = useState("");
  const [loading, setLoading] = useState(false);
  const [vault, setVault] = useState<VaultDetails | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleLookup() {
    if (!vaultId.trim()) {
      setError("Enter a Vault ID to look up.");
      return;
    }

    setLoading(true);
    setVault(null);
    setError(null);

    try {
      const obj = await client.getObject({
        id: vaultId.trim(),
        options: { showContent: true, showType: true },
      });

      if (!obj.data?.content || obj.data.content.dataType !== "moveObject") {
        throw new Error("Object not found or not a Move object.");
      }

      const fields = obj.data.content.fields as Record<string, unknown>;

      const nullifierPolicyValue = String(fields.nullifier_policy ?? "");
      const nullifierLabels: Record<string, string> = {
        "0": "One-time",
        "1": "Once-per-epoch",
        "2": "Unlimited",
      };

      const enclaves = fields.registered_enclave_pubkeys;
      const enclaveCount = Array.isArray(enclaves) ? enclaves.length : 0;

      const descBytes = fields.description;
      let description = "";
      if (Array.isArray(descBytes)) {
        description = new TextDecoder().decode(new Uint8Array(descBytes));
      } else if (typeof descBytes === "string") {
        description = descBytes;
      }

      const wasmHash = fields.wasm_double_hash;
      let wasmDoubleHash = "";
      if (Array.isArray(wasmHash)) {
        wasmDoubleHash =
          "0x" +
          (wasmHash as number[])
            .map((b: number) => b.toString(16).padStart(2, "0"))
            .join("");
      } else if (typeof wasmHash === "string") {
        wasmDoubleHash = wasmHash;
      }

      const sealPolicyId =
        typeof fields.seal_policy_id === "string"
          ? fields.seal_policy_id
          : String(fields.seal_policy_id ?? "");

      setVault({
        id: vaultId.trim(),
        owner: String(fields.owner ?? ""),
        paused: Boolean(fields.paused),
        proofValidityEpochs: String(fields.proof_validity_epochs ?? ""),
        nullifierPolicy:
          nullifierLabels[nullifierPolicyValue] ||
          `Unknown (${nullifierPolicyValue})`,
        description,
        enclaveCount,
        sealPolicyId,
        wasmDoubleHash,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={baseStyles.page}>
      <h2 style={baseStyles.h2}>Browse Vaults</h2>
      <div style={baseStyles.card}>
        <div style={baseStyles.field}>
          <label style={baseStyles.label}>Vault ID</label>
          <div style={{ display: "flex", gap: "12px" }}>
            <input
              style={{ ...baseStyles.input, flex: 1 }}
              value={vaultId}
              onChange={(e) => setVaultId(e.target.value)}
              placeholder="0x..."
              onKeyDown={(e) => {
                if (e.key === "Enter") handleLookup();
              }}
            />
            <button
              style={{
                ...baseStyles.button,
                ...(loading ? baseStyles.buttonDisabled : {}),
                whiteSpace: "nowrap",
              }}
              onClick={handleLookup}
              disabled={loading}
            >
              {loading ? "Loading..." : "Lookup"}
            </button>
          </div>
        </div>

        {error && (
          <div style={{ ...baseStyles.resultBox, ...baseStyles.errorBox }}>
            <strong>Error</strong>
            <br />
            {error}
          </div>
        )}

        {vault && (
          <div style={{ marginTop: "16px" }}>
            <DetailRow label="Vault ID" value={vault.id} />
            <DetailRow label="Owner" value={vault.owner} />
            <DetailRow
              label="Status"
              value={vault.paused ? "PAUSED" : "ACTIVE"}
              valueColor={vault.paused ? colors.error : colors.success}
            />
            <DetailRow
              label="Proof Validity"
              value={`${vault.proofValidityEpochs} epochs`}
            />
            <DetailRow label="Nullifier Policy" value={vault.nullifierPolicy} />
            <DetailRow label="Description" value={vault.description || "(none)"} />
            <DetailRow
              label="Registered Enclaves"
              value={String(vault.enclaveCount)}
            />
            <DetailRow label="Seal Policy ID" value={vault.sealPolicyId} />
            <DetailRow label="Wasm Double Hash" value={vault.wasmDoubleHash} />
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
  valueColor,
}: {
  label: string;
  value: string;
  valueColor?: string;
}) {
  return (
    <div style={baseStyles.detailRow}>
      <span style={baseStyles.detailLabel}>{label}</span>
      <span
        style={{
          ...baseStyles.detailValue,
          ...(valueColor ? { color: valueColor } : {}),
        }}
      >
        {value}
      </span>
    </div>
  );
}
