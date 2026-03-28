/**
 * Result of the first phase of Seal key loading.
 * Contains the encrypted key material that must be forwarded to the TEE.
 */
export interface SealKeyLoadInit {
  /** Encrypted key shares from the Seal DKS. */
  encryptedShares: Uint8Array;
  /** Session identifier for completing the load. */
  sessionId: string;
}

/**
 * Initiate Seal key loading for a TEE enclave.
 *
 * Phase 1 of the 2-phase Seal key load: the host fetches encrypted
 * key material from the Seal DKS via dry_run_transaction_block.
 * The result must be forwarded to the enclave via completeSealKeyLoad.
 *
 * @param vaultId - On-chain VaultConfig object ID
 * @param enclavePubkey - Ed25519 public key of the target TEE enclave
 * @param rpcUrl - Sui RPC endpoint URL
 * @returns Encrypted key material and session ID for phase 2
 */
export async function initSealKeyLoad(
  vaultId: string,
  enclavePubkey: Uint8Array,
  rpcUrl: string,
): Promise<SealKeyLoadInit> {
  void vaultId;
  void enclavePubkey;
  void rpcUrl;
  throw new Error("Not implemented");
}

/**
 * Complete Seal key loading by forwarding encrypted shares to the TEE.
 *
 * Phase 2 of the 2-phase Seal key load: the host sends the encrypted
 * key material to the TEE enclave, which decrypts it inside the
 * hardware security boundary.
 *
 * @param teeEndpoint - URL of the TEE enclave HTTP endpoint
 * @param sessionId - Session ID from initSealKeyLoad
 * @param encryptedShares - Encrypted shares from initSealKeyLoad
 */
export async function completeSealKeyLoad(
  teeEndpoint: string,
  sessionId: string,
  encryptedShares: Uint8Array,
): Promise<void> {
  void teeEndpoint;
  void sessionId;
  void encryptedShares;
  throw new Error("Not implemented");
}

/**
 * Load a circuit (wasm + proving key) into the TEE enclave.
 *
 * The enclave will verify the circuit artifacts match the hashes
 * registered in the on-chain VaultConfig before accepting them.
 *
 * @param teeEndpoint - URL of the TEE enclave HTTP endpoint
 * @param vaultId - On-chain VaultConfig object ID
 * @param wasmPath - Path to the circuit .wasm file
 * @param pkeyPath - Path to the Groth16 proving key file
 */
export async function loadCircuit(
  teeEndpoint: string,
  vaultId: string,
  wasmPath: string,
  pkeyPath: string,
): Promise<void> {
  void teeEndpoint;
  void vaultId;
  void wasmPath;
  void pkeyPath;
  throw new Error("Not implemented");
}
