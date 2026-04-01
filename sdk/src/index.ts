// Types
export type {
  VaultDeployParams,
  VaultConfig,
  VaultProof,
  ProveRequest,
  ProveResponse,
} from "./types.js";

// PVK processing & format conversion
export { computePvkComponents, convertProofToSui, convertPublicInputsToSui } from "./pvk.js";
export type { PvkComponents } from "./pvk.js";

// Circuit hashing
export { computeCircuitHashes } from "./hashes.js";
export type { CircuitHashes } from "./hashes.js";

// Vault management
export { deployVault, registerEnclaveForVault } from "./vault.js";

// Proof lifecycle
export {
  generateAndSubmitProof,
  verifyVaultProof,
  consumeProofWithResult,
} from "./proof.js";

// TEE administration: call TEE /admin/* endpoints directly via HTTP
// See tee/abyssal-prover/src/routes/admin.ts and seal-load.ts
