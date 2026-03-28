/**
 * Parameters for deploying a new Abyssal vault on-chain.
 */
export interface VaultDeployParams {
  vkJsonPath: string;
  wasmPath: string;
  sealPolicyId: string;
  proofValidityEpochs: number;
  nullifierPolicy: 0 | 1 | 2;
  description: string;
}

/**
 * On-chain vault configuration, mirroring the Move VaultConfig object.
 */
export interface VaultConfig {
  id: string;
  owner: string;
  pvkBytes: Uint8Array;
  circuitWasmHash: Uint8Array;
  circuitR1csHash: Uint8Array;
  sealPolicyId: string;
  proofValidityEpochs: number;
  nullifierPolicy: number;
  description: string;
}

/**
 * On-chain vault proof record, mirroring the Move VaultProof object.
 */
export interface VaultProof {
  id: string;
  vaultId: string;
  proofBytes: Uint8Array;
  publicInputsBytes: Uint8Array;
  teeSignature: Uint8Array;
  enclavePubkey: Uint8Array;
  submittedEpoch: number;
  expiryEpoch: number;
  nullifier: Uint8Array | null;
  verified: boolean;
}

/**
 * Request payload sent to the TEE enclave for proof generation.
 */
export interface ProveRequest {
  vaultId: string;
  privateInputs: Record<string, string>;
}

/**
 * Response from the TEE enclave after proof generation.
 */
export interface ProveResponse {
  proofBytes: Uint8Array;
  publicInputsBytes: Uint8Array;
  teeSignature: Uint8Array;
  enclavePubkey: Uint8Array;
}
