# Abyssal — Formal Specification v2.1.1

**Version:** 2.1.1
**Status:** Draft
**Author:** SuiCryptoLib (ARZER-TW)
**Predecessor:** zkVault v2.0.0
**Revision Date:** 2026/03/26

---

## Changelog

| Version | Description |
|---|---|
| 1.0.0 | Initial specification |
| 2.0.0 | Three architecture-level fixes: Nautilus attestation model, Seal IBE mechanism, PCR byte length |
| 2.1.0 | Renamed to Abyssal; vk/pvk size description fix; Move Poseidon API fix; pvk storage model fix; storage overhead annotation fix |
| 2.1.1 | Fix clock::epoch API (does not exist) to ctx.epoch(); unify epoch unit to Sui epoch (~24h); remove redundant Clock parameter from verify/consume functions; fastpath compatibility improvement |

---

## Table of Contents

1. Project Overview
2. Terminology
3. System Architecture Overview
4. Trust Model
5. Circuit Design Specification (VECS Standard)
6. Move Contract Specification
7. Seal Integration Specification
8. Walrus Storage Specification
9. Nautilus TEE Specification
10. SDK Specification
11. Deployment Process
12. User Usage Flow
13. Third-Party Protocol Integration Flow
14. Designated Auditor Verification Flow
15. Security Analysis & Threat Model
16. Performance Analysis
17. Known Limitations
18. Test Plan
19. Deliverables
20. Appendix A: Version Revision History

---

## 1. Project Overview

### 1.1 Problem Statement

There are two types of privacy problems in cryptography that have long been conflated:

**Data Privacy:** The computation logic is public, but the input data is hidden. Aztec, Aleo, and ZK Rollups solve this problem, and existing technology can already achieve it.

**Function Privacy (PFE, Private Function Evaluation):** Not only the input data is hidden, but **the computation logic itself is also hidden**, while the computation results can still be trusted and verified by anyone. This is known as PFE in academia, and no Web3 project has implemented a production-grade solution.

Traditional financial institutions' core competitiveness lies in their algorithms -- credit scoring models, risk control engines, compliance logic. These are decades of accumulated trade secrets worth hundreds of millions of dollars. They want to enter DeFi but face an unsolvable dilemma:

```
Option 1: Put the algorithm on a public chain
  -> Logic fully exposed, competitors can copy it in a day
  -> Institutions will refuse

Option 2: Maintain centralized service
  -> Users must blindly trust the institution
  -> No fundamental difference from Web2
```

This dilemma has no solution today. The real world uses "trusted intermediaries" (McKinsey, rating agencies, auditors) to work around it, and this market is worth hundreds of billions of dollars annually.

**Abyssal is the first Web3 protocol that makes "algorithm privacy, trusted results, no need to blindly trust intermediaries" simultaneously possible.**

### 1.2 Core Cryptographic Insight

Groth16's Trusted Setup produces two keys with fundamentally different properties:

```
Proving Key (pk)         5-50 MB
  Contains complete polynomial encoding of circuit logic
  Required to generate proofs
  Can be analyzed to reveal what the circuit does

Verification Key (vk)    Size depends on number of public inputs
  (About 600-800 bytes for 4 inputs)
  PreparedVerifyingKey (pvk) consists of 4 byte vectors,
  larger than raw vk but still far smaller than pk (5-50 MB)
  Can verify whether a proof is valid
  Mathematically impossible to reverse-engineer circuit logic
  (logic is encoded in pk only)
```

**The most critical fact: on-chain verification of a proof only needs pvk, not pk at all.**

Additionally, the witness calculator (`.wasm`) is machine code of the circuit logic, and reverse engineering can recover the circuit's computational structure.

Therefore, **true PFE requires simultaneously encrypting both pk and wasm, and the entire proof generation process must occur within a hardware security boundary.**

Abyssal's core insight:

> **Encrypt both pk and wasm with Seal IBE, and only allow Nautilus TEEs that have passed PCR attestation verification to decrypt and generate proofs. Deploy pvk on-chain so anyone can verify proof validity, but cannot infer what the circuit does.**

This has never been done before in the history of ZK applications.

### 1.3 Solution Overview

Abyssal achieves PFE through the following mechanisms:

1. **pk and wasm** are encrypted with Seal IBE and stored on Walrus
2. **Only Nautilus TEEs that pass PCR attestation verification** can decrypt pk/wasm and generate proofs
3. **pvk is deployed on-chain** (far smaller than pk), anyone can verify proof validity but cannot reverse-engineer circuit logic
4. **Public inputs are designed to be semantically opaque**, preventing indirect inference of circuit business logic

### 1.4 Scope

This specification covers: Move contract interfaces and data structures, Seal IBE integration scheme, Walrus storage design, Nautilus TEE design (including 2-phase Seal key load), JavaScript SDK, circuit design standard VECS, complete deployment and verification processes.

### 1.5 Out of Scope

- Specific Circom business logic circuit design (deployers implement their own, must comply with VECS standard)
- On-site execution of Trusted Setup Ceremony
- Nautilus TEE AWS production environment configuration (hackathon version uses mock)

---

## 2. Terminology

| Term | Definition |
|---|---|
| **PFE** | Private Function Evaluation, a computation protocol where the computation logic itself is invisible to unauthorized parties |
| **pk** | Proving Key, Groth16 proving key, 5-50 MB, contains complete polynomial encoding of circuit logic |
| **vk** | Verification Key, Groth16 verification key, size depends on number of public inputs (about 600-800 bytes for 4 inputs), mathematically impossible to reverse-engineer circuit logic |
| **pvk** | PreparedVerifyingKey, consists of 4 byte vectors (vk_gamma_abc_g1_bytes, alpha_g1_beta_g2_bytes, gamma_g2_neg_pc_bytes, delta_g2_neg_pc_bytes), reconstructed on-chain via `groth16::pvk_from_bytes`, input to `verify_groth16_proof` |
| **wasm** | Witness Calculator, machine code compiled from Circom circuit, executes witness computation |
| **PCR** | Platform Configuration Register, cryptographic fingerprint of AWS Nitro Enclave code, **48 bytes, SHA-384** |
| **EnclaveConfig** | Nautilus framework shared object, stores PCR0/1/2 (each 48 bytes SHA-384) and Cap ownership |
| **Enclave** | Nautilus framework shared object, stores TEE's ephemeral public key and metadata |
| **ephemeral keypair** | Ed25519 key pair generated inside enclave memory at TEE startup, private key never leaves enclave |
| **IBE** | Identity-Based Encryption, the encryption mechanism used by Seal |
| **2-phase key load** | Nautilus-Seal integration key loading process (init + complete), requires host as intermediary because enclave has no direct network access |
| **Vault** | An Abyssal instance created by a deployer, corresponding to a specific business logic circuit |
| **VaultProof** | A portable Sui object held by users after computation through Abyssal, representing a cryptographic credential of computation results |
| **Nullifier** | Anti-replay identifier, derived from user's private seed and vault information |
| **result_commitment** | Poseidon commitment of computation result, semantically opaque |
| **wasm_double_hash** | SHA-256(SHA-256(wasm_plaintext)), 32 bytes, used to verify TEE uses the correct circuit |
| **VECS** | Vault External Circuit Standard, Abyssal circuit interface standard |
| **Deployer** | Business logic owner, responsible for writing circuits and deploying Vaults |
| **Designated Auditor** | Specific persons authorized through Seal AuditPolicy who can decrypt circuit source code for complete auditing |

---

## 3. System Architecture Overview

### 3.1 Component Relationship Diagram

```
+----------------------------------------------------------------------+
|                          Business Logic Owner                         |
|  circuit.circom --> SuiCryptoLib Trusted Setup --> pk + wasm + vk     |
|                 --> Off-chain pre-compute pvk 4 components            |
+----------------------------+-------------------------+---------------+
                             |                         |
            +----------------+-------------+           |
            v                v             v           v
     +-----------+  +--------------+  +----------------------------+
     |  Walrus   |  |    Seal      |  |      Sui Move Contracts    |
     | (Mainnet) |  |  (Mainnet)   |  |                            |
     |           |  |              |  |  VaultConfig               |
     | Encrypted |  | IBE master   |  |   pvk (4 byte vectors)    |
     | pk        |  | public key   |  |   wasm_double_hash (32B)  |
     | Encrypted |  | seal_approve |  |   registered_enclave_ids  |
     | wasm      |  | Move policy  |  |   pk_blob_id/wasm_blob_id |
     | Encrypted |  |              |  |                            |
     | circuit   |  | DKS: Testnet |  |  EnclaveConfig             |
     | source    |  | Mainnet uses |  |   pcr0/1/2 (48B each)     |
     | (audit)   |  | single key   |  |                            |
     |           |  | server       |  |  Enclave                   |
     +-----+-----+  +------+------+  |   ephemeral_pubkey         |
            |               |         +----------------------------+
            +---------------+---------------------+
                            |                     |
                            v                     |
                 +----------------------+         |
                 |   Nautilus TEE        |<--------+
                 | (AWS Nitro Enclave)   |   On-chain verification
                 |                      |
                 | Generates 3 keypairs:|
                 |  1. ephemeral Ed25519|
                 |  2. Seal wallet Ed25519
                 |  3. ElGamal encryption
                 |                      |
                 | 2-phase Seal key load|
                 | (host as intermediary)|
                 |                      |
                 | Decrypts pk + wasm   |
                 | Verifies wasm_double_hash
                 | Computes witness     |
                 | Generates Groth16 proof
                 | Ed25519 signs output |
                 +----------+-----------+
                            |
         +------------------+------------------+
         v                  v                  v
    192B Proof        Ed25519 Signature    Public Inputs
    (Groth16)         (ephemeral key,     (4 x 32 bytes)
                       64 bytes)          nullifier +
                            |              result_commit +
                            |              vault_id_hash +
                            |              expiry_epoch
                            v
                 +----------------------+
                 |    Sui Move Verify    |
                 |                      |
                 | 1. Confirm Enclave   |
                 |    registered        |
                 | 2. Ed25519 sig verify|
                 | 3. Nullifier check   |
                 | 4. Groth16 verify    |
                 | -> Issue VaultProof  |
                 +----------------------+
```

### 3.2 SuiCryptoLib's Role in Abyssal

SuiCryptoLib is Abyssal's engineering infrastructure layer:

- Provides Groth16 format conversion pipeline (Circom format -> Sui Move `sui::groth16` input format)
- Provides off-chain pre-computation tools for pvk's 4 components (avoids high gas `prepare_verifying_key` on-chain)
- Provides existing circuits (`hash_commitment`, `range_proof`, `semaphore`, `threshold_range`) that can be combined with Abyssal output proofs
- Provides `abyssal` Move modules: vault registry, proof object definition, on-chain verification interface
- Provides complete JavaScript SDK

### 3.3 Sui Groth16 API Key Limitations (Confirmed by Official Docs)

- **Maximum 8 public inputs** (VECS uses 4, within the limit)
- Supports BN254 and BLS12-381 curves (Abyssal uses BN254)
- Key APIs: `prepare_verifying_key` (off-chain pre-computation), `pvk_from_bytes` (on-chain reconstruction), `proof_points_from_bytes`, `public_proof_inputs_from_bytes`, `verify_groth16_proof`

---

## 4. Trust Model

### 4.1 Trust Eliminated by Abyssal

| Traditional Centralized Model | Abyssal Model |
|---|---|
| Trust that institution "hasn't secretly changed rules" | pvk fixed on-chain, each proof corresponds to same logic, mathematically guaranteed |
| Trust that institution "applies same standards to all users" | Same pvk, circuit has no dynamic branches, mathematically identical |
| Trust that institution "hasn't leaked user data" | Data processed within TEE hardware boundary, never goes on-chain |
| Trust that audit reports are truthful | Designated auditors independently confirm through five-layer verification chain, no need to trust any report |

### 4.2 Remaining Trust Assumptions (Must Be Honestly Stated in All External Documents)

| Trust Assumption | Description | Deployer Mitigations |
|---|---|---|
| AWS Nitro Enclave hardware | Assumes hardware has no backdoors or major security flaws | Common assumption for all TEE solutions |
| Seal key server honesty | Hackathon: single key server; Production: DKS t-of-n | Increase t value and node count |
| TEE source code correctness | Source code provided to auditors matches binary corresponding to PCR | Auditors independently recompile from source to verify PCR |

### 4.3 Security Degradation Boundaries

**TEE Hardware Compromised:**
- Worst case: Algorithm logic (pk/wasm plaintext) leaked, commercial loss
- Asset safety: **Completely unaffected**. Attacker with pk still needs valid witness satisfying all constraints to generate proof, cannot forge proofs for users who don't meet conditions
- This is Abyssal's fundamental security advantage over pure TEE privacy solutions (Secret Network, Phala)

**Seal Compromised (collusion exceeding threshold):**
- Worst case: pk/wasm leaked, circuit logic exposed
- Asset safety: **Also unaffected** (same analysis as TEE compromise)

---

## 5. Circuit Design Specification (VECS Standard)

### 5.1 Public Inputs Interface Standard

Every circuit deployed to Abyssal **must** follow this structure to ensure semantic opacity:

```
Public Inputs (in this order, exactly 4, within Groth16's 8 input limit):

[0] nullifier          32 bytes (BN254 field element)
    = Poseidon([user_secret, vault_id_field, epoch])
    Anti-replay, reveals no business semantics

[1] result_commitment  32 bytes (BN254 field element)
    = Poseidon([result_value, result_salt])
    Result commitment, semantically opaque, reveals nothing about result meaning

[2] vault_id_hash      32 bytes (BN254 field element)
    = Poseidon([vault_id_field])
    Prevents cross-vault replay

[3] expiry_epoch       32 bytes (BN254 field element, value is u64)
    Proof validity expiry in Sui epochs (~24h per epoch), reveals no business semantics
```

### 5.2 Semantic Opacity Requirements

**Forbidden designs (leak business semantics):**

```
X  min_credit_score: 700    -> Leaks: checking credit score
X  approved: bool           -> Leaks: it's an approval system
X  income_verified: bool    -> Leaks: verifying income
X  threshold: u64           -> Leaks: there's a numerical threshold
```

**Requirement:** All business semantics must be entirely contained in private inputs, committed through `result_commitment`, and not appear in any readable form in public inputs.

### 5.3 Circuit Template (VECS-compliant)

```circom
pragma circom 2.1.5;
include "circomlib/circuits/poseidon.circom";

// Deployers implement specific business logic within this framework
// VALIDITY_DURATION is in Sui epochs (~24h each)
// e.g. VALIDITY_DURATION = 28 means ~28 days validity
template AbyssalBase(VALIDITY_DURATION) {
    // ===== Standard Private Inputs =====
    signal input user_secret;
    signal input vault_id_field;
    signal input epoch;           // Current Sui epoch number
    signal input result_value;    // Business logic result (semantics defined by deployer)
    signal input result_salt;
    // Additional business logic private inputs defined by sub-templates...

    // ===== Standard Public Outputs (4, within Groth16's 8 limit) =====
    signal output nullifier;
    signal output result_commitment;
    signal output vault_id_hash;
    signal output expiry_epoch;

    // ===== Nullifier Computation =====
    component nh = Poseidon(3);
    nh.inputs[0] <== user_secret;
    nh.inputs[1] <== vault_id_field;
    nh.inputs[2] <== epoch;
    nullifier <== nh.out;

    // ===== Result Commitment Computation =====
    component rh = Poseidon(2);
    rh.inputs[0] <== result_value;
    rh.inputs[1] <== result_salt;
    result_commitment <== rh.out;

    // ===== Vault ID Hash Computation =====
    component vh = Poseidon(1);
    vh.inputs[0] <== vault_id_field;
    vault_id_hash <== vh.out;

    // ===== Expiry Epoch =====
    // VALIDITY_DURATION unit is Sui epoch (~24h each)
    // e.g. VALIDITY_DURATION = 28 means ~28 days validity
    expiry_epoch <== epoch + VALIDITY_DURATION;

    // ===== Business Logic Constraints =====
    // Sub-templates verify business logic here, output conclusion to result_value
    // result_value semantics are completely opaque on-chain
}
```

**Note:** `Poseidon(N)` syntax in Circom is correct. Move contract side uses different API (see Section 6).

### 5.4 Constraint Estimation Guidelines

| Circuit Complexity | Constraints | TEE Proof Generation Time | Recommended Scenarios |
|---|---|---|---|
| Simple | < 50,000 | < 5s | Basic eligibility verification |
| Medium | 50,000 - 500,000 | 5-30s | Credit scoring, compliance screening |
| Complex | 500,000 - 2,000,000 | 30-120s | Complex risk control models |
| **Beyond recommended** | > 2,000,000 | > 120s | **Not recommended for Abyssal** |

---

## 6. Move Contract Specification

### 6.1 Module Structure

```
suicryptolib::abyssal
    +-- abyssal_registry    Vault lifecycle management (core)
    +-- abyssal_proof       VaultProof object definition & verification (core)
    +-- abyssal_types       Shared data types
    +-- abyssal_events      Event definitions
```

### 6.2 Core Data Structures

```move
module suicryptolib::abyssal_registry {
    use sui::groth16::{Self, PreparedVerifyingKey};
    use sui::table::{Self, Table};
    use sui::clock::Clock;
    use sui::ed25519;
    use sui::poseidon;
    use sui::bcs;

    // ===== Error Codes =====
    const EInvalidProof: u64 = 0;
    const EInvalidTEESignature: u64 = 1;
    const EWrongCircuit: u64 = 2;
    const ENullifierUsed: u64 = 3;
    const EProofExpired: u64 = 4;
    const EVaultPaused: u64 = 5;
    const EUnauthorized: u64 = 6;
    const EInvalidVaultIdHash: u64 = 7;
    const EEnclaveNotRegistered: u64 = 8;
    const EInvalidPublicInputLength: u64 = 9;
    const EEpochOutOfRange: u64 = 10;

    // ===== VaultConfig (Core Shared Object) =====
    public struct VaultConfig has key {
        id: UID,

        owner: address,
        description: vector<u8>,
        version: u64,
        paused: bool,

        // Groth16 verification key (4 byte vectors)
        // Reconstructed via pvk_from_bytes, pre-computed off-chain then deployed
        pvk: PreparedVerifyingKey,

        // Circuit identity (semantically opaque)
        // SHA-256(SHA-256(wasm_plaintext)), 32 bytes
        // Verified at Enclave registration, NOT at every proof submission
        wasm_double_hash: vector<u8>,

        // Encrypted pk/wasm locations on Walrus
        pk_blob_id: vector<u8>,
        wasm_blob_id: vector<u8>,

        // Seal policy object ID
        seal_policy_id: ID,

        // Registered Nautilus Enclave object IDs
        // Each ID points to an Enclave object that has completed attestation verification
        registered_enclave_ids: vector<ID>,

        // Proof validity period (unit: Sui epoch, ~24h per epoch)
        // e.g. proof_validity_epochs = 28 means ~28 days
        // NOTE: This uses Sui epochs (NOT Walrus epochs), because
        // on-chain epoch is obtained via ctx.epoch() which returns Sui epoch
        proof_validity_epochs: u64,

        // Nullifier policy: 0=one-time, 1=once-per-epoch, 2=unlimited
        nullifier_policy: u8,

        // Nullifier records (anti-replay)
        used_nullifiers: Table<vector<u8>, bool>,
    }

    // ===== VaultProof (Portable Computation Credential Held by Users) =====
    public struct VaultProof has key, store {
        id: UID,
        vault_id: ID,

        // Semantically opaque public inputs (4 BN254 field elements)
        nullifier: vector<u8>,           // 32 bytes
        result_commitment: vector<u8>,   // 32 bytes
        vault_id_hash: vector<u8>,       // 32 bytes
        expiry_epoch: u64,

        // Original proof (for re-submission when reusing across protocols)
        proof_bytes: vector<u8>,         // 128 bytes Groth16 proof (BN254 compressed: A=32 + B=64 + C=32)
        public_inputs_bytes: vector<u8>, // 4 x 32 = 128 bytes

        // Enclave object ID that produced this proof (audit trail)
        enclave_id: ID,
    }
```

### 6.3 Vault Lifecycle Functions

```move
    // ===== Create Vault =====
    // pvk's 4 components are pre-computed off-chain by SDK
    // (avoids high-gas prepare_verifying_key on-chain)
    public fun create_vault(
        vk_gamma_abc_g1_bytes: vector<u8>,   // pvk component 1
        alpha_g1_beta_g2_bytes: vector<u8>,  // pvk component 2
        gamma_g2_neg_pc_bytes: vector<u8>,   // pvk component 3
        delta_g2_neg_pc_bytes: vector<u8>,   // pvk component 4
        wasm_double_hash: vector<u8>,        // SHA-256(SHA-256(wasm)), 32 bytes
        pk_blob_id: vector<u8>,              // Walrus blob ID (encrypted pk)
        wasm_blob_id: vector<u8>,            // Walrus blob ID (encrypted wasm)
        seal_policy_id: ID,
        proof_validity_epochs: u64,
        nullifier_policy: u8,
        description: vector<u8>,
        ctx: &mut TxContext,
    ): ID {
        // Reconstruct PreparedVerifyingKey on-chain via pvk_from_bytes (low gas)
        let pvk = groth16::pvk_from_bytes(
            vk_gamma_abc_g1_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
        );

        let config = VaultConfig {
            id: object::new(ctx),
            owner: ctx.sender(),
            description,
            version: 1,
            paused: false,
            pvk,
            wasm_double_hash,
            pk_blob_id,
            wasm_blob_id,
            seal_policy_id,
            registered_enclave_ids: vector::empty(),
            proof_validity_epochs,
            nullifier_policy,
            used_nullifiers: table::new(ctx),
        };

        let vault_id = object::id(&config);
        transfer::share_object(config);
        vault_id
    }

    // ===== Register an Enclave that has completed Nautilus attestation =====
    public fun register_enclave_for_vault(
        vault: &mut VaultConfig,
        enclave_id: ID,
        enclave_wasm_double_hash: vector<u8>,
        ctx: &TxContext,
    ) {
        assert!(vault.owner == ctx.sender(), EUnauthorized);
        assert!(
            enclave_wasm_double_hash == vault.wasm_double_hash,
            EWrongCircuit
        );
        assert!(
            !vector::contains(&vault.registered_enclave_ids, &enclave_id),
            EUnauthorized
        );
        vector::push_back(&mut vault.registered_enclave_ids, enclave_id);

        event::emit(EnclaveRegisteredForVault {
            vault_id: object::id(vault),
            enclave_id,
        });
    }

    // ===== Unregister Enclave (when TEE is retired) =====
    public fun unregister_enclave_from_vault(
        vault: &mut VaultConfig,
        enclave_id: ID,
        ctx: &TxContext,
    ) {
        assert!(vault.owner == ctx.sender(), EUnauthorized);
        let (found, idx) = vector::index_of(&vault.registered_enclave_ids, &enclave_id);
        if (found) {
            vector::remove(&mut vault.registered_enclave_ids, idx);
        };
    }

    // ===== Pause / Resume =====
    public fun pause_vault(vault: &mut VaultConfig, ctx: &TxContext) {
        assert!(vault.owner == ctx.sender(), EUnauthorized);
        vault.paused = true;
        event::emit(VaultPaused { vault_id: object::id(vault) });
    }

    public fun resume_vault(vault: &mut VaultConfig, ctx: &TxContext) {
        assert!(vault.owner == ctx.sender(), EUnauthorized);
        vault.paused = false;
        event::emit(VaultResumed { vault_id: object::id(vault) });
    }
```

### 6.4 Proof Submission Function (Core)

**Design principle: attestation verification is done only once at TEE registration (high gas); here only Ed25519 signature verification (low gas).**

```move
    // ===== Submit Proof, receive VaultProof object =====
    public fun submit_proof(
        vault: &mut VaultConfig,
        enclave: &nautilus_enclave::Enclave,  // Nautilus Enclave object (contains ephemeral_pubkey)
        groth16_proof_bytes: vector<u8>,      // 128 bytes Groth16 proof (BN254 compressed: A=32 + B=64 + C=32)
        public_inputs_bytes: vector<u8>,      // 4 x 32 = 128 bytes
        tee_signature: vector<u8>,            // TEE ephemeral key Ed25519 signature of (proof||inputs), 64 bytes
        ctx: &mut TxContext,
    ): VaultProof {
        // Step 1: Confirm vault is not paused
        assert!(!vault.paused, EVaultPaused);

        // Step 2: Confirm enclave is registered with this vault
        let enclave_id = object::id(enclave);
        assert!(
            vector::contains(&vault.registered_enclave_ids, &enclave_id),
            EEnclaveNotRegistered
        );

        // Step 3: Read ephemeral_pubkey from Nautilus Enclave object
        let ephemeral_pubkey = nautilus_enclave::get_pubkey_bytes(enclave);

        // Step 4: Verify TEE Ed25519 signature
        // message = proof_bytes || public_inputs_bytes
        let mut message = groth16_proof_bytes;
        vector::append(&mut message, public_inputs_bytes);
        assert!(
            ed25519::ed25519_verify(&tee_signature, &ephemeral_pubkey, &message),
            EInvalidTEESignature
        );

        // Step 5: Verify public_inputs_bytes length (4 field elements = 128 bytes)
        assert!(
            vector::length(&public_inputs_bytes) == 128,
            EInvalidPublicInputLength
        );

        // Step 6: Parse 4 public inputs
        let nullifier = extract_bytes(&public_inputs_bytes, 0, 32);
        let result_commitment = extract_bytes(&public_inputs_bytes, 32, 32);
        let vault_id_hash = extract_bytes(&public_inputs_bytes, 64, 32);
        let expiry_epoch = le_bytes_to_u64(extract_bytes(&public_inputs_bytes, 96, 32));

        // Step 7: Verify vault_id_hash
        // Poseidon_bn254([vault_id_as_u256]) should equal vault_id_hash in public input
        // NOTE: Sui's poseidon_bn254 accepts vector<u256>, returns u256
        // vault_id must be reduced modulo BN254_R (poseidon aborts if input >= field order)
        let vault_id_bytes = object::id_to_bytes(&object::id(vault));
        let vault_id_u256 = bytes32_to_u256(vault_id_bytes) % BN254_R;
        let expected_vault_id_hash_u256 = poseidon::poseidon_bn254(
            &vector[vault_id_u256]
        );
        let expected_vault_id_hash = u256_to_bytes32(expected_vault_id_hash_u256);
        assert!(vault_id_hash == expected_vault_id_hash, EInvalidVaultIdHash);

        // Step 8: Verify epoch validity
        // NOTE: Uses ctx.epoch() to get Sui epoch (~24h per epoch)
        // sui::clock::Clock does NOT provide epoch() -- only timestamp_ms()
        let current_epoch = ctx.epoch();
        assert!(current_epoch <= expiry_epoch, EProofExpired);
        assert!(
            expiry_epoch <= current_epoch + vault.proof_validity_epochs,
            EEpochOutOfRange
        );

        // Step 9: Verify nullifier based on nullifier_policy
        if (vault.nullifier_policy == 0 || vault.nullifier_policy == 1) {
            assert!(
                !table::contains(&vault.used_nullifiers, nullifier),
                ENullifierUsed
            );
            table::add(&mut vault.used_nullifiers, nullifier, true);
        };

        // Step 10: Verify Groth16 proof
        let proof_points = groth16::proof_points_from_bytes(groth16_proof_bytes);
        let public_proof_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);
        assert!(
            groth16::verify_groth16_proof(
                &groth16::bn254(),
                &vault.pvk,
                &public_proof_inputs,
                &proof_points
            ),
            EInvalidProof
        );

        // Step 11: Build and return VaultProof object
        let proof_obj = VaultProof {
            id: object::new(ctx),
            vault_id: object::id(vault),
            nullifier,
            result_commitment,
            vault_id_hash,
            expiry_epoch,
            proof_bytes: groth16_proof_bytes,
            public_inputs_bytes,
            enclave_id,
        };

        event::emit(ProofSubmitted {
            vault_id: object::id(vault),
            proof_id: object::id(&proof_obj),
            enclave_id,
            nullifier,
            expiry_epoch,
        });

        proof_obj
    }
```

### 6.5 Proof Consumption Functions (For Third-Party Protocols)

```move
    // ===== Verify VaultProof validity (non-consuming, can be called repeatedly) =====
    // NOTE: Uses ctx.epoch() instead of Clock, because sui::clock has no epoch()
    // ctx.epoch() returns Sui epoch (~24h), does NOT require consensus (fastpath compatible)
    public fun verify_vault_proof(
        vault: &VaultConfig,
        proof: &VaultProof,
        ctx: &TxContext,
    ): bool {
        if (proof.vault_id != object::id(vault)) return false;
        ctx.epoch() <= proof.expiry_epoch
    }

    // ===== Consume VaultProof (reveal result, one-time use, object destroyed) =====
    public fun consume_proof_with_result(
        vault: &VaultConfig,
        proof: VaultProof,               // move semantics: consumed and destroyed
        result_value_bytes: vector<u8>,  // User reveals computation result
        result_salt_bytes: vector<u8>,   // User reveals salt
        ctx: &mut TxContext,
    ): vector<u8> {
        assert!(verify_vault_proof(vault, &proof, ctx), EProofExpired);

        // Verify result_commitment = Poseidon_bn254([result_value, result_salt])
        // NOTE: Sui poseidon_bn254 accepts vector<u256>, returns u256
        let rv_u256 = bytes_to_u256(result_value_bytes);
        let rs_u256 = bytes_to_u256(result_salt_bytes);
        let computed_u256 = poseidon::poseidon_bn254(&vector[rv_u256, rs_u256]);
        let computed_bytes = u256_to_bytes32(computed_u256);
        assert!(computed_bytes == proof.result_commitment, EInvalidProof);

        event::emit(ProofConsumed {
            vault_id: proof.vault_id,
            proof_id: object::id(&proof),
            consumer: ctx.sender(),
        });

        let result = result_value_bytes;

        // Destroy VaultProof object
        let VaultProof {
            id, vault_id: _, nullifier: _, result_commitment: _,
            vault_id_hash: _, expiry_epoch: _, proof_bytes: _,
            public_inputs_bytes: _, enclave_id: _,
        } = proof;
        object::delete(id);

        result
    }

    // ===== Helper Functions (internal use) =====
    fun extract_bytes(data: &vector<u8>, offset: u64, len: u64): vector<u8> {
        let mut result = vector::empty<u8>();
        let mut i = offset;
        while (i < offset + len) {
            vector::push_back(&mut result, *vector::borrow(data, i));
            i = i + 1;
        };
        result
    }

    // NOTE: bytes32_to_u256, u256_to_bytes32, bytes_to_u256, le_bytes_to_u64
    // These helper functions ensure consistency with Circom circuit's BN254
    // field element representation (little-endian, 32 bytes)
    // Full implementations in suicryptolib::abyssal_types module
```

### 6.6 Event Definitions

```move
module suicryptolib::abyssal_events {
    public struct VaultCreated has copy, drop {
        vault_id: ID,
        owner: address,
        seal_policy_id: ID,
        pk_blob_id: vector<u8>,
        wasm_blob_id: vector<u8>,
    }

    public struct EnclaveRegisteredForVault has copy, drop {
        vault_id: ID,
        enclave_id: ID,
    }

    public struct EnclaveUnregisteredFromVault has copy, drop {
        vault_id: ID,
        enclave_id: ID,
    }

    public struct ProofSubmitted has copy, drop {
        vault_id: ID,
        proof_id: ID,
        enclave_id: ID,
        nullifier: vector<u8>,
        expiry_epoch: u64,
    }

    public struct ProofConsumed has copy, drop {
        vault_id: ID,
        proof_id: ID,
        consumer: address,
    }

    public struct VaultPaused has copy, drop { vault_id: ID }
    public struct VaultResumed has copy, drop { vault_id: ID }
}
```

---

## 7. Seal Integration Specification

### 7.1 Seal Working Principle (Based on Official Docs, 2026/03)

Seal uses **Identity-Based Encryption (IBE)**:

```
Encryption:
  encrypt(data, identity, IBE_master_public_key)
  identity = bytes identifier (Abyssal uses vector[0u8])

Decryption:
  Requester builds PTB, calls seal_approve(id, ...)
  Seal key server executes seal_approve via dry_run_transaction_block (read-only, no state changes)
  If passes -> returns derived decryption key (encrypted under ElGamal public key)
  Only the party holding the corresponding ElGamal private key (the enclave) can decrypt
```

**Key properties:**
- `seal_approve` function name must start with `seal_approve`
- First parameter must be `id: vector<u8>` (inner bytes of IBE identity)
- Evaluated via `dry_run_transaction_block`, read-only, no on-chain state changes
- IBE schemes and symmetric encryption handled by Seal SDK, application layer need not concern itself

### 7.2 Nautilus-Seal Integration Key Constraint

**Nautilus enclave has no direct network access.** Seal key server is accessed via HTTP, which the enclave cannot call directly.

Official Nautilus-Seal example solution: **host as trusted intermediary (2-phase key load)**

```
TEE generates 3 key pairs on startup (all in enclave memory, never leave enclave):
  1. ephemeral Ed25519 keypair (signs /process_data responses)
  2. Seal wallet Ed25519 keypair (authenticates with Seal)
  3. ElGamal encryption key pair (receives Seal encrypted derived key)

Phase 1 (init_seal_key_load):
  enclave builds seal_approve PTB:
    - sig = ephemeral_privkey.sign(intent_message(wallet_pubkey, timestamp))
    - PTB transaction sender = Seal wallet address
  enclave returns via host's /admin/init_seal_key_load:
    FetchKeyRequest = { ptb, elgamal_public_key }

Phase 2 (complete_seal_key_load):
  host (NOT enclave) calls Seal CLI: seal fetch-keys --request FetchKeyRequest
  Seal key server dry-runs seal_approve -> passes -> returns FetchKeyResponse
    (FetchKeyResponse encrypted under ElGamal public key, only enclave can decrypt)
  host passes FetchKeyResponse to /admin/complete_seal_key_load
  enclave decrypts with ElGamal private key, caches Seal derived key in enclave memory

Why this is secure:
  - FetchKeyResponse encrypted under enclave's ElGamal public key
  - host cannot decrypt (no ElGamal private key)
  - seal_approve PTB signed by enclave ephemeral key
  - only this enclave (knowing ephemeral private key) can construct valid seal_approve PTB
```

### 7.3 Abyssal's seal_approve Design

```move
module suicryptolib::abyssal_seal_policy {
    use sui::clock::Clock;
    use sui::ed25519;
    use sui::bcs;

    // seal_approve verifies: is the TEE requesting decryption a registered Enclave of this Vault?
    // This function is called by Seal key server via dry_run_transaction_block
    entry fun seal_approve(
        id: vector<u8>,
        enclave: &nautilus_enclave::Enclave,
        vault_config: &abyssal_registry::VaultConfig,
        wallet_pubkey: vector<u8>,
        timestamp: u64,
        sig: vector<u8>,
        clock: &Clock,
    ) {
        // Verify 1: key ID is fixed value vector[0]
        assert!(id == vector[0u8], ENoAccess);

        // Verify 2: enclave is registered in VaultConfig
        assert!(
            vector::contains(
                vault_config.registered_enclave_ids(),
                &object::id(enclave)
            ),
            ENoAccess
        );

        // Verify 3: timestamp within reasonable window (anti-replay)
        let current_time_ms = clock::timestamp_ms(clock);
        assert!(
            current_time_ms <= timestamp + 60_000,  // 60 second window
            ENoAccess
        );

        // Verify 4: ephemeral key signature on (wallet_pubkey || timestamp) is valid
        let mut message = wallet_pubkey;
        vector::append(&mut message, bcs::to_bytes(&timestamp));
        let ephemeral_pubkey = nautilus_enclave::get_pubkey_bytes(enclave);
        assert!(
            ed25519::ed25519_verify(&sig, &ephemeral_pubkey, &message),
            ENoAccess
        );

        // All verifications pass -> Seal key server releases derived key
        // (encrypted under ElGamal pubkey)
    }

    const ENoAccess: u64 = 0;
}
```

**Note:** `seal_approve` correctly uses `clock::timestamp_ms(clock)` for time checks (not epoch). The `Clock` object is valid and necessary here for millisecond-precision timestamp verification.

### 7.4 Encryption Storage Format (IBE)

```typescript
// Encrypt with Seal SDK at deployment time (TypeScript)
import { SealClient } from '@mysten/seal';

const sealClient = new SealClient({
    suiClient,
    serverConfigs: [{
        objectId: SEAL_KEY_SERVER_OBJECT_ID,
        weight: 1,
    }],
    verifyKeyServers: false, // set to true for production
});

// Encrypt pk (IBE identity = vector[0], matches id in seal_approve)
const pkEncrypted = await sealClient.encrypt({
    data: pkBytes,
    packageId: ABYSSAL_SEAL_POLICY_PACKAGE_ID,
    id: new Uint8Array([0]),
});

// Encrypt wasm (same settings)
const wasmEncrypted = await sealClient.encrypt({
    data: wasmBytes,
    packageId: ABYSSAL_SEAL_POLICY_PACKAGE_ID,
    id: new Uint8Array([0]),
});
// Encrypted bytes uploaded directly to Walrus
```

### 7.5 Designated Auditor Seal Policy (Separate Policy)

```move
module suicryptolib::abyssal_audit_policy {
    public struct AuditAllowlist has key {
        id: UID,
        vault_id: ID,
        authorized_auditors: vector<address>,
        owner: address,
    }

    entry fun seal_approve(
        id: vector<u8>,
        allowlist: &AuditAllowlist,
        clock: &Clock,
        ctx: &TxContext,
    ) {
        assert!(
            vector::contains(&allowlist.authorized_auditors, &ctx.sender()),
            ENoAccess
        );
        event::emit(AuditAccess {
            vault_id: allowlist.vault_id,
            auditor: ctx.sender(),
            timestamp_ms: clock::timestamp_ms(clock),
        });
    }

    const ENoAccess: u64 = 0;

    public struct AuditAccess has copy, drop {
        vault_id: ID,
        auditor: address,
        timestamp_ms: u64,
    }
}
```

### 7.6 Decentralized Key Server Status (As of 2026/03/26)

| Environment | Seal Status | Abyssal Usage |
|---|---|---|
| Testnet | DKS available (launched 2026/03/12), 3-of-5 threshold | Use DKS directly |
| Mainnet | DKS not yet supported | Use single key server (or multiple independent key servers) |

**Production path:** After DKS launches on Mainnet, migrating from single key server to DKS only requires updating `SealClient`'s `serverConfigs`. Application code and Move contracts **require no changes**.

---

## 8. Walrus Storage Specification

### 8.1 Walrus Basic Facts (Confirmed by Official Docs, 2026/03)

- **Mainnet epoch duration: 2 weeks (14 days)**
- **Testnet epoch duration: 1 day**
- **Maximum storage period: 53 epochs (Mainnet ~2 years)**
- **Storage overhead: ~5x (estimate, based on Red Stuff 2D erasure coding design)**
- **All blobs are public by default**, must encrypt with Seal IBE first to protect content confidentiality
- **Blob ID** is content-addressed (deterministically derived from Walrus configuration and blob content), any content change changes the blob ID
- **Blob objects** are Sui objects with `certified_epoch`, `Storage` (containing `start_epoch`, `end_epoch`)

### 8.2 Abyssal's Walrus Storage Structure

Each Vault's Walrus storage consists of 3 blobs (all encrypted with Seal IBE before upload):

```
Vault Walrus Blobs
|
+-- pk_blob (Seal IBE encrypted, VaultKeyPolicy controls access)
|   blob_id = Walrus deterministic ID (derived from encrypted content)
|   Original pk size: 5-50 MB
|   Walrus storage overhead: ~25-250 MB (~5x, estimate)
|   Recommended storage period: 52 epochs (~2 years, below 53 epoch maximum)
|
+-- wasm_blob (Seal IBE encrypted, VaultKeyPolicy controls access)
|   blob_id = Walrus deterministic ID
|   Original wasm size: 50-500 KB
|   Recommended storage period: 52 epochs
|
+-- circuit_source_blob (Seal IBE encrypted, AuditAllowlistPolicy controls access)
    blob_id = Walrus deterministic ID
    Original size: < 1 MB
    Recommended storage period: 52 epochs
    NOTE: This blob uses a separate AuditAllowlistPolicy, different from VaultKeyPolicy
```

### 8.3 Blob ID Security Significance

Walrus blob ID is deterministically derived from encrypted blob content, therefore:

- The `pk_blob_id` recorded on-chain is the identity of the encrypted blob
- Any modification to blob content changes the blob ID, invalidating on-chain references
- This guarantees that pk/wasm encrypted content cannot be silently replaced
- Auditors can independently verify that the Walrus blob corresponds to the on-chain recorded blob ID

### 8.4 Blob Storage Period Management

```bash
# Query blob status (including remaining epochs)
walrus blob-status <blob_id> --context mainnet

# Extend blob storage period (uses Sui object ID, not blob ID)
walrus extend \
    --blob-obj-id <blob_sui_object_id> \
    --epochs-extended 26 \
    --context mainnet
```

---

## 9. Nautilus TEE Specification

### 9.1 Nautilus Architecture Principles (Confirmed by Official Docs, 2026/03)

**Official documentation explicitly states:**
> "Verify attestation documents on-chain only during enclave registration due to high gas costs. After registration, use the enclave key for more efficient message verification."

**Two core Move objects:**
- `EnclaveConfig`: Stores PCR0/1/2 (each **48 bytes, SHA-384**) and Cap object
- `Enclave`: Stores ephemeral public key and metadata (needs update after each TEE restart)

**PCR definitions (based on official docs):**
- **PCR0**: OS and boot environment (48 bytes, SHA-384)
- **PCR1**: Application code (48 bytes, SHA-384)
- **PCR2**: Runtime configuration (`run.sh`, traffic rules) (48 bytes, SHA-384)

### 9.2 TEE Internal Key Generation

TEE generates **3 key pairs** inside enclave memory at startup (none leave enclave):

```
1. ephemeral Ed25519 keypair:
   - public key included in attestation, stored on-chain in Enclave object
   - used to sign every /process_data response, Move contract verifies this signature

2. Seal wallet Ed25519 keypair:
   - serves as transaction sender for seal_approve PTB
   - address derived from wallet pubkey

3. ElGamal encryption key pair (BLS group elements):
   - public key sent to Seal, used to encrypt returned derived key
   - private key only in enclave memory, only enclave can decrypt Seal response
```

### 9.3 TEE Complete Workflow (Pseudocode)

#### Phase 1: TEE Startup and Nautilus Framework Registration (One-Time)

```rust
fn startup() {
    // 1. Generate 3 key pairs inside enclave memory
    let eph_keypair = Ed25519KeyPair::generate();
    let seal_wallet = Ed25519KeyPair::generate();
    let elgamal_keys = ElGamalKeyPair::generate();

    // 2. Expose /get_attestation endpoint
    // Attestation document (AWS Nitro format) contains:
    //   PCR0/1/2 (each 48 bytes, SHA-384)
    //   public_key = eph_keypair.public_key (ephemeral key)
    //   user_data = SHA-256(SHA-256(wasm_plaintext)) = wasm_double_hash (32 bytes)

    // 3. Admin uses attestation to call Nautilus register_enclave on-chain:
    //    (high gas, done only once)
    //    - Verifies complete AWS CA certificate chain
    //    - Confirms PCR values are correct
    //    - Creates EnclaveConfig object (PCR0/1/2)
    //    - Creates Enclave object (eph_keypair.public_key)

    // 4. Admin calls Abyssal's register_enclave_for_vault:
    //    - Reads Enclave's user_data (wasm_double_hash)
    //    - Verifies wasm_double_hash == VaultConfig.wasm_double_hash
    //    - Adds Enclave ID to registered_enclave_ids
}
```

#### Phase 2: 2-Phase Seal Key Load (Because Enclave Has No Network Access)

```rust
fn init_seal_key_load(
    enclave_obj_id: SuiObjectID,
    enclave_obj_version: u64
) -> FetchKeyRequest {
    let timestamp = current_timestamp_ms();

    let mut intent_msg = seal_wallet.public_key_bytes().to_vec();
    intent_msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = eph_keypair.sign(&intent_msg);

    let ptb = build_seal_approve_ptb(
        id: vec![0u8],
        enclave_obj: (enclave_obj_id, enclave_obj_version),
        vault_config: ...,
        wallet_pubkey: seal_wallet.public_key_bytes(),
        timestamp: timestamp,
        sig: sig,
    );

    FetchKeyRequest {
        ptb,
        encryption_pubkey: elgamal_keys.public_key_bytes(),
    }
}

fn complete_seal_key_load(fetch_key_response: FetchKeyResponse) {
    let derived_key = elgamal_keys.decrypt(fetch_key_response);
    CACHED_SEAL_DERIVED_KEY = derived_key;
}
```

#### Phase 3: Circuit Decryption and Consistency Verification (Once After TEE Startup)

```rust
fn load_circuit() {
    let pk_encrypted = walrus_fetch_via_host(PK_BLOB_ID);
    let wasm_encrypted = walrus_fetch_via_host(WASM_BLOB_ID);

    let pk = seal_decrypt(pk_encrypted, CACHED_SEAL_DERIVED_KEY);
    let wasm = seal_decrypt(wasm_encrypted, CACHED_SEAL_DERIVED_KEY);

    // Internal circuit consistency verification
    let wasm_hash = sha256(wasm);
    let wasm_double_hash = sha256(wasm_hash);
    assert!(
        wasm_double_hash == COMMITTED_WASM_DOUBLE_HASH,
        "Circuit integrity check failed"
    );

    CACHED_PK = pk;
    CACHED_WASM = wasm;
}
```

#### Phase 4: Each Proof Generation (/process_data)

```rust
fn process_data(user_request: EncryptedUserRequest) -> ProcessDataResponse {
    // 1. Decrypt user request
    let (vault_id, private_inputs, user_secret, result_salt, epoch) =
        decrypt_user_request(user_request);

    // 2. Business logic computation
    let result_value = run_business_logic(private_inputs);

    // 3. Prepare circuit inputs (all private, never leave enclave)
    let circuit_inputs = CircuitInputs {
        user_secret,
        vault_id_field: object_id_to_field(vault_id),
        epoch,  // Current Sui epoch number (obtained from chain via SDK)
        result_value,
        result_salt,
    };

    // 4. Compute witness inside enclave (using cached WASM)
    let witness = calculate_witness(CACHED_WASM, circuit_inputs);

    // 5. Generate Groth16 proof inside enclave (using cached PK)
    let (proof, public_inputs) = groth16_prove(CACHED_PK, witness);

    // 6. Serialize
    let proof_bytes = serialize_proof(proof);                  // 128 bytes (BN254 compressed)
    let inputs_bytes = serialize_public_inputs(public_inputs); // 128 bytes

    // 7. Sign with ephemeral key
    // message = proof_bytes || inputs_bytes (320 bytes total)
    let mut message = proof_bytes.clone();
    message.extend_from_slice(&inputs_bytes);
    let tee_signature = eph_keypair.sign(&message); // 64 bytes Ed25519 signature

    // 8. Return results (contains NO private data)
    ProcessDataResponse {
        proof_bytes,
        public_inputs_bytes: inputs_bytes,
        tee_signature,
    }
    // User's original data and computation intermediates all stay in enclave memory
}
```

### 9.4 Attestation User Data Specification

```
AWS Nitro Enclave attestation user_data field (up to 1024 bytes):

Abyssal usage:
  user_data = SHA-256(SHA-256(wasm_plaintext))  // 32 bytes

Purpose:
  - At TEE registration (register_enclave_for_vault), Move contract reads
    Enclave object's user_data and compares with VaultConfig.wasm_double_hash
  - Ensures "the TEE using this PCR" also "uses the correct wasm circuit"

Non-auditors see: 32-byte hash, cannot know what circuit it corresponds to
Auditors can: hold wasm -> compute SHA-256(wasm) -> compute SHA-256(SHA-256(wasm))
              compare with on-chain VaultConfig.wasm_double_hash for consistency
```

### 9.5 PCR Whitelist Maintenance

```
Each time TEE program version is upgraded:
  1. Recompile enclave image
     make ENCLAVE_APP=abyssal-prover
     cat out/nitro.pcrs  -> get new PCR0/1/2 (each 48 bytes hex)

  2. Call Nautilus framework's update_pcrs, update EnclaveConfig

  3. Re-execute TEE startup and Nautilus framework registration (new Enclave object)

  4. Call register_enclave_for_vault to register new Enclave in VaultConfig

  5. Optional: unregister_enclave_from_vault to remove old Enclave registration

Note: After TEE restart, ephemeral key changes, must re-register_enclave
      Existing VaultProof objects remain valid within their validity period
      (proofs do not depend on ephemeral key)
```

---

## 10. SDK Specification

### 10.1 JavaScript SDK Main APIs

```typescript
// @suicryptolib/sdk/abyssal

// ===== Type Definitions =====

interface AbyssalVaultConfig {
    circuitPath: string;
    zkeyPath: string;
    wasmPath: string;
    circuitSourcePath: string;
    sealKeyServerObjectId: string;
    walrusEpochs: number;           // Walrus storage period (recommend 52, ~2 years, max 53)
    proofValidityEpochs: number;    // VaultProof validity in Sui epochs (~24h each)
    nullifierPolicy: 0 | 1 | 2;
    description: string;
    network: 'mainnet' | 'testnet';
}

interface AbyssalVaultDeployResult {
    vaultId: string;
    sealPolicyId: string;
    auditPolicyId: string;
    pkBlobId: string;
    wasmBlobId: string;
    circuitSourceBlobId: string;
    wasmDoubleHash: string;
    pvkComponents: {
        vkGammaAbcG1Bytes: string;
        alphaG1BetaG2Bytes: string;
        gammaG2NegPcBytes: string;
        deltaG2NegPcBytes: string;
    };
    txDigest: string;
}

interface ProofRequest {
    vaultId: string;
    enclaveId: string;
    enclaveUrl: string;
    privateInputs: Record<string, string>;
    userSecret: string;
    resultSalt: string;
}

interface ProofResult {
    proofObjectId: string;
    nullifier: string;
    resultCommitment: string;
    expiryEpoch: number;       // Sui epoch number
    txDigest: string;
}

// ===== Main APIs =====

export async function computePvkComponents(
    vkBytes: Uint8Array,
): Promise<{
    vkGammaAbcG1Bytes: Uint8Array;
    alphaG1BetaG2Bytes: Uint8Array;
    gammaG2NegPcBytes: Uint8Array;
    deltaG2NegPcBytes: Uint8Array;
}>;

export async function computeCircuitHashes(wasmPath: string): Promise<{
    wasmHash: string;
    wasmDoubleHash: string;
}>;

export async function deployVault(
    config: AbyssalVaultConfig,
    auditorAddresses: string[],
    wallet: WalletAdapter,
): Promise<AbyssalVaultDeployResult>;

export async function registerEnclaveForVault(
    vaultId: string,
    enclaveId: string,
    wallet: WalletAdapter,
): Promise<{ txDigest: string }>;

export async function generateAndSubmitProof(
    request: ProofRequest,
    wallet: WalletAdapter,
): Promise<ProofResult>;

export async function verifyVaultProof(
    proofObjectId: string,
    vaultId: string,
    network: 'mainnet' | 'testnet',
): Promise<{ valid: boolean; expiryEpoch: number }>;

export async function consumeProofWithResult(
    proofObjectId: string,
    vaultId: string,
    resultValue: string,
    resultSalt: string,
    wallet: WalletAdapter,
): Promise<{ result: string; txDigest: string }>;

export async function auditVault(
    vaultId: string,
    wallet: WalletAdapter,
): Promise<{
    circuitSource: string;
    r1csHash: string;
    wasmHash: string;
    wasmDoubleHash: string;
    recomputedVkComponents: {
        vkGammaAbcG1Bytes: string;
        alphaG1BetaG2Bytes: string;
        gammaG2NegPcBytes: string;
        deltaG2NegPcBytes: string;
    };
    chainPvkMatch: boolean;
    consistent: boolean;
}>;

export async function checkBlobStatus(
    vaultId: string,
    network: 'mainnet' | 'testnet',
): Promise<{
    pkBlobCertified: boolean;
    pkEndEpoch: number;           // Walrus epoch
    wasmBlobCertified: boolean;
    wasmEndEpoch: number;         // Walrus epoch
    currentWalrusEpoch: number;
    epochsUntilExpiry: number;
}>;
```

### 10.2 CLI Tools

```bash
# Compute circuit hashes
suicryptolib abyssal compute-circuit-hashes --wasm ./circuit.wasm

# Pre-compute pvk components (off-chain)
suicryptolib abyssal compute-pvk --vk ./vk.json --output ./pvk_components.json

# Deploy complete Abyssal Vault
suicryptolib abyssal deploy \
  --circuit ./credit_score.circom \
  --zkey ./credit_score_final.zkey \
  --wasm ./credit_score_js/credit_score.wasm \
  --circuit-source ./credit_score.circom \
  --seal-key-server <KEY_SERVER_OBJ_ID> \
  --walrus-epochs 52 \
  --proof-validity-epochs 28 \
  --nullifier-policy 1 \
  --auditor <AUDITOR_ADDRESS_1> \
  --auditor <AUDITOR_ADDRESS_2> \
  --description "Financial eligibility assessment" \
  --network testnet

# Register TEE to Vault
suicryptolib abyssal register-enclave --vault-id 0x... --enclave-id 0x... --network testnet

# Check blob storage status
suicryptolib abyssal check-blob-status --vault-id 0x... --network testnet

# Audit Vault (must be in AuditAllowlist)
suicryptolib abyssal audit --vault-id 0x... --network testnet --output ./audit_report.json
```

---

## 11. Deployment Process

```
Phase 1: Circuit Preparation
--------------------------------------------------------------
Step 1.1  Design business logic circuit (.circom), comply with VECS standard
Step 1.2  Compile: circom circuit.circom --r1cs --wasm --sym
Step 1.3  Compute circuit hashes:
          suicryptolib abyssal compute-circuit-hashes --wasm circuit_js/circuit.wasm

Phase 2: Trusted Setup
--------------------------------------------------------------
Step 2.1  Choose Powers of Tau (recommend using Hermez PoT)
Step 2.2  Initialize Phase 2:
          snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit_0000.zkey
Step 2.3  Deployer contribution (mandatory)
Step 2.4  Designated auditors each contribute one round (strongly recommended)
Step 2.5  Final random beacon (use public randomness)
Step 2.6  Export final vk:
          snarkjs zkey export verificationkey circuit_final.zkey vk.json
Step 2.7  Off-chain pre-compute pvk 4 components:
          suicryptolib abyssal compute-pvk --vk vk.json --output pvk_components.json

Phase 3: Seal Policy and Audit Allowlist Deployment
--------------------------------------------------------------
Step 3.1  Deploy VaultKeyPolicy (with seal_approve logic) to Sui
Step 3.2  Deploy AuditAllowlist (designated auditor address list) to Sui

Phase 4: Walrus Encrypted Storage
--------------------------------------------------------------
Step 4.1  Encrypt and upload pk to Walrus (using VaultKeyPolicy)
Step 4.2  Encrypt and upload wasm to Walrus (using VaultKeyPolicy)
Step 4.3  Encrypt and upload circuit source to Walrus (using AuditAllowlistPolicy)

Phase 5: Deploy VaultConfig to Sui
--------------------------------------------------------------
Step 5.1  Deploy VaultConfig using pre-computed pvk components + pvk_from_bytes

Phase 6: Deploy and Register Nautilus TEE
--------------------------------------------------------------
Step 6.1  Configure seal_config.yaml (inside TEE)
Step 6.2  Compile enclave image, get PCR values
Step 6.3  Deploy Nautilus enclave framework contracts
Step 6.4  Update PCR whitelist and deploy enclave to AWS Nitro
Step 6.5  TEE startup, get attestation, register_enclave on-chain (high gas, one-time)
Step 6.6  Execute 2-phase Seal key load (via admin endpoints)
Step 6.7  TEE decrypts and caches circuit

Phase 7: VaultConfig Register Enclave
--------------------------------------------------------------
Step 7.1  Register Enclave to VaultConfig (SDK auto-verifies wasm_double_hash)

Phase 8: Verify Deployment
--------------------------------------------------------------
Step 8.1  Public verification (anyone can execute)
Step 8.2  Designated auditors execute five-layer verification (see Section 14)
Step 8.3  End-to-end functional test
```

---

## 12. User Usage Flow

```
Step 1: Prepare Private Inputs (local, never leave device)
  Generate userSecret (high-entropy random) locally
  Generate resultSalt (high-entropy random) locally
  Prepare private input data required by business logic

Step 2: Generate VaultProof via TEE
  const result = await abyssalSDK.generateAndSubmitProof({
    vaultId: '0x...',
    enclaveId: '0x...',
    enclaveUrl: 'https://tee.example.com',
    privateInputs: { income: '120000', debt: '40000', ... },
    userSecret: localSecret,
    resultSalt: localResultSalt,
  }, wallet);

  NOTE: The epoch input to TEE should be the current Sui epoch value
  (obtained from chain via SDK). Sui epoch updates ~every 24 hours,
  different from Walrus epoch (2 weeks).

  TEE internal execution (transparent to user):
    Accept encrypted input -> business logic -> witness computation
    -> Groth16 proof generation -> ephemeral key signing -> return output
    User's raw data never leaves TEE hardware boundary

Step 3: Receive VaultProof object
  {
    proofObjectId: '0x...',
    nullifier: '0xabc...',
    resultCommitment: '0xdef...',
    expiryEpoch: 42,             // Sui epoch number
    txDigest: '...',
  }

Step 4: Use VaultProof

  Mode A (multi-protocol reuse, don't reveal result):
    Submit proofObjectId to protocol
    Protocol calls verify_vault_proof to check validity
    Same proof can be reused across multiple protocols before expiryEpoch

  Mode B (reveal result and consume):
    Submit proofObjectId + resultValue + resultSalt to protocol
    Protocol calls consume_proof_with_result:
      Verifies Poseidon(resultValue, resultSalt) == result_commitment
      Executes business logic (e.g. disburse loan)
      VaultProof object destroyed (one-time use)
```

---

## 13. Third-Party Protocol Integration Flow

### 13.1 Minimal Integration Example (Move Contract)

```move
use suicryptolib::abyssal_proof::{VaultProof};
use suicryptolib::abyssal_registry::{VaultConfig};

// DeFi lending protocol example using VaultProof
public fun apply_for_loan(
    vault: &VaultConfig,
    proof: VaultProof,
    result_value_bytes: vector<u8>,
    result_salt_bytes: vector<u8>,
    loan_amount: u64,
    loan_pool: &mut LoanPool,
    ctx: &mut TxContext,
) {
    // 1. Consume VaultProof, verify result_commitment, get result
    let result = abyssal_proof::consume_proof_with_result(
        vault, proof, result_value_bytes, result_salt_bytes, ctx,
    );

    // 2. Decide business logic based on result
    // result semantics defined by vault deployer (coordinated in advance, not on-chain)
    assert!(result == b"1", EApplicationDenied);

    // 3. Execute business
    assert!(loan_amount <= loan_pool.available_amount(), EInsufficientFunds);
    disburse_loan(loan_pool, ctx.sender(), loan_amount, ctx);
}
```

### 13.2 Multi-Use Pattern (Don't Consume Proof)

```move
public fun check_eligibility(
    vault: &VaultConfig,
    proof: &VaultProof,
    ctx: &TxContext,
): bool {
    // Only verify proof validity, don't consume object
    abyssal_proof::verify_vault_proof(vault, proof, ctx)
}
```

### 13.3 Integration Notes

1. **Confirm vault_id source:** Ensure the vault is created by a trusted deployer
2. **Understand result semantics:** Query deployer in advance for result_value meanings (not on-chain)
3. **Choose correct usage mode:** Multi-reuse -> `verify_vault_proof`; reveal result -> `consume_proof_with_result`
4. **Don't try to infer circuit logic:** Do not attempt to infer what the circuit does from pvk, proof, or public inputs

---

## 14. Designated Auditor Verification Flow (Five-Layer Verification Chain)

Designated auditors independently verify through five layers, **without trusting anyone's verbal claims**:

### Layer 1: Circuit Content Confirmation (Decrypt Source from Seal)

```bash
suicryptolib abyssal audit --vault-id 0x... --network testnet --output ./audit/
circom ./audit/circuit.circom --r1cs --wasm
# Compute wasm_double_hash and compare with on-chain VaultConfig.wasm_double_hash
```

### Layer 2: pvk Binding Confirmation (Recompute pvk from Circuit)

```bash
snarkjs zkey export verificationkey ./audit/circuit_final.zkey ./audit/vk_recomputed.json
suicryptolib abyssal compute-pvk --vk ./audit/vk_recomputed.json --output ./audit/pvk_recomputed.json
# Compare 4 components with on-chain VaultConfig.pvk
```

### Layer 3: TEE Self-Report Confirmation (wasm_double_hash Consistency)

```bash
# Verify on-chain VaultConfig.wasm_double_hash matches Enclave object's user_data
```

### Layer 4: PCR Value Confirmation (TEE Code Audit)

```bash
make ENCLAVE_APP=abyssal-prover
cat out/nitro.pcrs
# Compare PCR0/1/2 with on-chain EnclaveConfig
```

### Layer 5: Trusted Setup Ceremony Participation

```bash
snarkjs zkey contribute circuit_N.zkey circuit_N+1.zkey --name="Auditor Org" -v
# Security: as long as at least one participant is honest, setup is secure
```

---

## 15. Security Analysis & Threat Model

### 15.1 Attacker Class 1: Public Observer

**Defense:** pvk mathematically cannot reverse-engineer circuit logic. Public inputs are semantically opaque.

### 15.2 Attacker Class 2: Malicious User

**Defense:** Groth16 soundness (cannot generate valid proof without pk). Nullifier prevents replay. vault_id_hash prevents cross-vault replay.

### 15.3 Attacker Class 3: Compromised TEE

**Algorithm leak:** Commercial loss only. **Asset safety: completely unaffected** -- attacker with pk still needs valid witness satisfying all constraints.

### 15.4 Attacker Class 4: Malicious Deployer

**Defense:** pvk fixed on-chain. Any circuit change changes pvk. Same pvk guarantees mathematical consistency for all users.

### 15.5 Attacker Class 5: Compromised Seal

**Defense:** Same as 15.3 -- algorithm logic may leak, but asset safety unaffected.

### 15.6 Behavioral Side-Channel Analysis

**Cannot be fully eliminated.** Large sample observation may statistically partially reveal circuit behavior. Mitigation: differential privacy at business logic layer (deployer responsibility).

---

## 16. Performance Analysis

### 16.1 Latency Estimates

| Phase | Latency | Notes |
|---|---|---|
| 2-phase Seal key load | 5-30s (one-time) | PTB build + Seal HTTP + ElGamal decrypt |
| Walrus pk download (~50 MB) | 2-10s (one-time) | Cacheable in enclave memory |
| Witness computation (medium circuit) | 1-5s | TEE CPU |
| Groth16 proof generation (medium) | 5-30s | TEE CPU/GPU |
| Ed25519 signature verification (Move) | ~1 ms | Fixed cost |
| Groth16 on-chain verification (Move) | ~50-100 ms | Fixed cost, 2 BN254 pairings |
| **End-to-end (TEE cached)** | **~7-40s** | |
| **End-to-end (TEE first startup)** | **~15-60s** | Including pk/wasm download |

NOTE: expiry_epoch uses Sui epochs (~24h), NOT Walrus epochs (2 weeks).
e.g. proof_validity_epochs = 28 means ~28 days validity (28 Sui epochs).
Walrus epochs are only used for blob storage period calculation (see Section 8).

### 16.2 On-Chain Verification Cost Estimates (To Be Updated After Testnet Testing)

| Operation | Gas Estimate | Notes |
|---|---|---|
| TEE initial register_enclave | High (one-time) | Full attestation verification |
| `create_vault` | ~1,000,000 MIST | pvk_from_bytes reconstruction (low gas) |
| `submit_proof` | ~3,000,000 MIST | Ed25519 + Groth16 + Nullifier write |
| `verify_vault_proof` (read) | ~300,000 MIST | Read-only, no state write, fastpath compatible |
| `consume_proof_with_result` | ~1,500,000 MIST | Poseidon verify + object destroy |

### 16.3 Proof Size

| Data | Size |
|---|---|
| Groth16 proof | 128 bytes (BN254 compressed, fixed) |
| Public inputs (4 x 32 bytes) | 128 bytes |
| TEE Ed25519 signature | 64 bytes |
| **On-chain submission payload** | **384 bytes** |
| **VaultProof object (on-chain storage)** | **~700 bytes + Sui object overhead** |

---

## 17. Known Limitations

| Limitation | Impact | Mitigation Direction |
|---|---|---|
| Groth16 proof generation latency (5-60s) | Not suitable for high-frequency real-time scenarios | Hardware acceleration (GPU/FPGA) |
| TEE ephemeral key changes on restart | Must re-register_enclave | Persistent TEE operation; automation scripts |
| TEE restart requires re-doing 2-phase key load | Operational complexity | Persistent TEE operation |
| Seal DKS currently Testnet only | Mainnet uses single key server | Wait for DKS on Mainnet |
| Behavioral side-channel analysis | May statistically partially reveal circuit behavior | Differential privacy (business layer) |
| Walrus blob storage period maintenance | Blob expiry -> pk/wasm unavailable | SDK auto-monitoring and alerts |
| TEE trust assumption | AWS Nitro hardware backdoor (theoretical risk) | Common assumption for all TEE solutions |

---

## 18. Test Plan

### 18.1 Move Contract Unit Tests

| ID | Description |
|---|---|
| T-01 | `test_create_vault_valid` |
| T-02 | `test_create_vault_invalid_pvk_format` |
| T-03 | `test_submit_proof_valid` |
| T-04 | `test_submit_proof_invalid_groth16` |
| T-05 | `test_submit_proof_invalid_tee_signature` |
| T-06 | `test_submit_proof_unregistered_enclave` |
| T-07 | `test_submit_proof_wrong_vault_id_hash` |
| T-08 | `test_submit_proof_expired_epoch` |
| T-09 | `test_submit_proof_epoch_out_of_range` |
| T-10 | `test_nullifier_replay_fails` |
| T-11 | `test_nullifier_policy_unlimited` |
| T-12 | `test_verify_vault_proof_valid` |
| T-13 | `test_verify_vault_proof_expired` |
| T-14 | `test_verify_vault_proof_wrong_vault` |
| T-15 | `test_consume_proof_correct_result` |
| T-16 | `test_consume_proof_wrong_result` |
| T-17 | `test_consume_proof_wrong_salt` |
| T-18 | `test_vault_pause_rejects_proof` |
| T-19 | `test_vault_resume_accepts_proof` |
| T-20 | `test_register_enclave_wrong_wasm_hash` |
| T-21 | `test_register_enclave_duplicate_rejected` |
| T-22 | `test_unregister_enclave` |
| T-23 | `test_unauthorized_vault_operations` |
| T-24 | `test_public_input_length_validation` |
| T-25 | `test_proof_object_reuse_via_verify` |

### 18.2 SDK Integration Tests

| ID | Description |
|---|---|
| IT-01 | computePvkComponents + deployVault end-to-end |
| IT-02 | vk -> pvk 4 components -> pvk_from_bytes round-trip correctness |
| IT-03 | generateAndSubmitProof full flow (mock TEE) |
| IT-04 | auditVault five-layer verification flow |
| IT-05 | checkBlobStatus query |
| IT-06 | registerEnclaveForVault with wasm_double_hash verification |

### 18.3 E2E Tests

| ID | Scenario |
|---|---|
| E2E-01 | Deploy credit score vault -> user gets VaultProof -> DeFi protocol consumes proof and lends |
| E2E-02 | Same VaultProof verified by two different protocols (not consumed, multi-reuse) |
| E2E-03 | Auditor executes complete five-layer verification |
| E2E-04 | TEE restart, re-register_enclave, existing VaultProof still valid |

---

## 19. Deliverables

### Hackathon Version (4-5 weeks)

**Move Contracts:**
- [ ] `suicryptolib::abyssal_registry`
- [ ] `suicryptolib::abyssal_proof`
- [ ] `suicryptolib::abyssal_types`
- [ ] `suicryptolib::abyssal_seal_policy`
- [ ] `suicryptolib::abyssal_audit_policy`
- [ ] `suicryptolib::abyssal_events`

**Circuit:**
- [ ] Test credit score circuit (VECS-compliant, ~50,000 constraints)

**SDK (TypeScript):**
- [ ] `@suicryptolib/sdk/abyssal` (all APIs)
- [ ] CLI tools

**TEE (mock version):**
- [ ] Nautilus TEE program (abyssal-prover)
- [ ] `#[test_only]` mock functions

**Demo:**
- [ ] Credit score vault + DeFi lending protocol frontend

**Tests:**
- [ ] Move unit tests T-01 to T-25
- [ ] E2E-01

**Documentation:**
- [ ] This SPEC document (v2.1.1)
- [ ] README.md
- [ ] ARCHITECTURE.md

**Known simplifications (clearly labeled):**
1. Nautilus TEE uses mock instead of real AWS Nitro Enclave
2. Seal uses Testnet DKS or single key server

---

## 20. Appendix A: Version Revision History

### v1.0.0 -> v2.0.0 (Three Architecture-Level Fixes)

| # | Issue | v1.0.0 | v2.0.0 | Level |
|---|---|---|---|---|
| R-01 | Nautilus on-chain verification model | Full attestation per submit_proof | Attestation only at TEE registration; Ed25519 signature after | Architecture |
| R-02 | Nautilus data structures | VaultConfig stores PCR whitelist | VaultConfig stores registered_enclave_ids, PCR in EnclaveConfig | Architecture |
| R-03 | Seal mechanism | No IBE description, assumed traditional asymmetric | Explicit IBE; Nautilus-Seal needs 2-phase key load | Architecture |
| R-04 | Seal function name | `approve` | `seal_approve` | Medium |
| R-05 | PCR byte length | 32 bytes (SHA-256) | **48 bytes (SHA-384)** | Medium |
| R-06 | Walrus epoch | Unspecified | Mainnet = **2 weeks**; Testnet = 1 day | Low |
| R-07 | Groth16 public inputs limit | Unspecified | Maximum **8** (VECS uses 4) | Low |
| R-08 | Seal DKS status | Described as primary option | DKS currently Testnet only (launched 2026/03/12) | Low |
| R-09 | wasm_double_hash verification timing | Every proof verification | Once at TEE registration | Medium |

### v2.0.0 -> v2.1.0 (Four Technical Detail Fixes + Rename)

| # | Issue | v2.0.0 | v2.1.0 | Level |
|---|---|---|---|---|
| P-00 | Project rename | zkVault | **Abyssal** | -- |
| P-01 | vk/pvk size description | "vk ~128 bytes" | vk ~600-800 bytes (4 inputs); pvk is 4 byte vectors | High |
| P-02 | Move Poseidon API | `poseidon::poseidon_N(...)` | **`poseidon::poseidon_bn254(&vector[...])`** | High |
| P-03 | pvk storage method | Raw vk passed, on-chain prepare_verifying_key (high gas) | 4 pre-computed components, on-chain **`pvk_from_bytes`** (low gas) | Medium |
| P-04 | Storage overhead description | "~5x" | "~5x (estimate)" | Low |

### v2.1.0 -> v2.1.1 (API Fix + Epoch Unit Unification)

| # | Issue | v2.1.0 | v2.1.1 | Level |
|---|---|---|---|---|
| Q-01 | clock::epoch does not exist | `clock::epoch(clock)` | **`ctx.epoch()`** (from TxContext) | High |
| Q-02 | Redundant Clock parameter in verify/consume | `clock: &Clock` for epoch access | Removed Clock, use **`ctx: &TxContext`** epoch() | High |
| Q-03 | Epoch unit confusion | proof_validity_epochs labeled as Walrus epoch (2 weeks) | Changed to **Sui epoch (~24h)**; Walrus epoch only for blob storage | Medium |

---

## Final One-Line Positioning

> **Abyssal is the first Web3 protocol to achieve production-grade "Private Function Evaluation (PFE)" -- by simultaneously encrypting the Groth16 proving key and wasm (Seal IBE + Walrus), allowing only PCR-attested Nautilus TEEs to decrypt and generate proofs via 2-phase key load within hardware security boundaries, deploying pvk on-chain for anyone to verify result legitimacy (Ed25519 + Groth16 dual verification), and making VaultProof a cross-protocol portable Sui object -- achieving "circuit logic privacy, trusted computation results, independent five-layer verification by designated auditors" simultaneously for the first time -- an architecture that relies on native integration of SuiCryptoLib + Seal + Walrus + Nautilus, a capability unique to the Sui ecosystem that cannot be replicated the same way on any other chain.**
