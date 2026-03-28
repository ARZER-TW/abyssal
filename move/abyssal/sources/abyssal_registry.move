/// Abyssal Registry — Vault lifecycle management and proof submission.
///
/// VaultConfig is the core shared object. It stores:
/// - pvk (PreparedVerifyingKey, 4 byte vectors, reconstructed via pvk_from_bytes)
/// - wasm_double_hash (circuit identity, 32 bytes)
/// - Encrypted pk/wasm blob IDs on Walrus
/// - Registered enclave public keys (hackathon: stored directly, production: Nautilus Enclave objects)
/// - Nullifier records (Table)
///
/// submit_proof verifies: enclave signature + Groth16 proof + nullifier + epoch + vault_id_hash
/// then issues a VaultProof Sui object to the caller.
#[allow(unused_variable)]
module abyssal::abyssal_registry {
    use sui::groth16;
    use sui::ed25519;
    use sui::poseidon;
    use sui::table::{Self, Table};
    use sui::event;
    use abyssal::abyssal_types;
    // Events defined inline (Sui requires event structs in same module as emit)

    // BN254 scalar field order (poseidon_bn254 requires inputs < this value)
    const BN254_R: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ===== Error Codes =====
    const EInvalidProof: u64 = 0;
    const EInvalidTEESignature: u64 = 1;
    const ENullifierUsed: u64 = 2;
    const EProofExpired: u64 = 3;
    const EVaultPaused: u64 = 4;
    const EUnauthorized: u64 = 5;
    const EInvalidVaultIdHash: u64 = 6;
    const EEnclaveNotRegistered: u64 = 7;
    const EInvalidPublicInputLength: u64 = 8;
    const EEpochOutOfRange: u64 = 9;
    const EWrongCircuit: u64 = 10;
    const EDuplicateEnclave: u64 = 11;

    // ===== Events =====
    public struct VaultCreated has copy, drop {
        vault_id: ID, owner: address, seal_policy_id: ID,
        pk_blob_id: vector<u8>, wasm_blob_id: vector<u8>,
        circuit_source_blob_id: vector<u8>,
    }
    public struct EnclaveRegistered has copy, drop { vault_id: ID, enclave_pubkey: vector<u8> }
    public struct EnclaveUnregistered has copy, drop { vault_id: ID, enclave_pubkey: vector<u8> }
    public struct ProofSubmitted has copy, drop {
        vault_id: ID, proof_id: ID, nullifier: vector<u8>, expiry_epoch: u64,
    }
    public struct ProofConsumed has copy, drop { vault_id: ID, proof_id: ID, consumer: address }
    #[allow(unused_field)]
    public struct VaultPaused has copy, drop { vault_id: ID }
    #[allow(unused_field)]
    public struct VaultResumed has copy, drop { vault_id: ID }

    // ===== VaultConfig =====
    public struct VaultConfig has key {
        id: UID,
        owner: address,
        description: vector<u8>,
        version: u64,
        paused: bool,

        // Groth16 PreparedVerifyingKey (4 components, reconstructed via pvk_from_bytes)
        pvk: groth16::PreparedVerifyingKey,

        // Circuit identity: SHA-256(SHA-256(wasm_plaintext)), 32 bytes
        wasm_double_hash: vector<u8>,

        // Encrypted pk/wasm/circuit-source on Walrus
        pk_blob_id: vector<u8>,
        wasm_blob_id: vector<u8>,
        circuit_source_blob_id: vector<u8>,

        // Seal policy object ID
        seal_policy_id: ID,

        // Registered enclave public keys (hackathon: Ed25519 pubkeys stored directly)
        // Production: would reference Nautilus Enclave object IDs
        registered_enclave_pubkeys: vector<vector<u8>>,

        // Proof validity period (Sui epochs, ~24h each)
        proof_validity_epochs: u64,

        // Nullifier policy: 0=one-time, 1=once-per-epoch, 2=unlimited
        nullifier_policy: u8,

        // Nullifier records
        used_nullifiers: Table<vector<u8>, bool>,
    }

    // ===== VaultProof (portable computation credential) =====
    public struct VaultProof has key, store {
        id: UID,
        vault_id: ID,

        // 4 semantically opaque public inputs (BN254 field elements)
        nullifier: vector<u8>,           // 32 bytes
        result_commitment: vector<u8>,   // 32 bytes
        vault_id_hash: vector<u8>,       // 32 bytes
        expiry_epoch: u64,

        // Original proof (for re-verification across protocols)
        proof_bytes: vector<u8>,         // 192 bytes
        public_inputs_bytes: vector<u8>, // 128 bytes

        // Which enclave produced this proof (audit trail)
        enclave_pubkey: vector<u8>,
    }

    // ===== Create Vault =====
    public fun create_vault(
        vk_gamma_abc_g1_bytes: vector<u8>,
        alpha_g1_beta_g2_bytes: vector<u8>,
        gamma_g2_neg_pc_bytes: vector<u8>,
        delta_g2_neg_pc_bytes: vector<u8>,
        wasm_double_hash: vector<u8>,
        pk_blob_id: vector<u8>,
        wasm_blob_id: vector<u8>,
        circuit_source_blob_id: vector<u8>,
        seal_policy_id: ID,
        proof_validity_epochs: u64,
        nullifier_policy: u8,
        description: vector<u8>,
        ctx: &mut TxContext,
    ): ID {
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
            circuit_source_blob_id,
            seal_policy_id,
            registered_enclave_pubkeys: vector::empty(),
            proof_validity_epochs,
            nullifier_policy,
            used_nullifiers: table::new(ctx),
        };

        let vault_id = object::id(&config);

        event::emit(VaultCreated {
            vault_id,
            owner: ctx.sender(),
            seal_policy_id,
            pk_blob_id,
            wasm_blob_id,
            circuit_source_blob_id,
        });

        transfer::share_object(config);
        vault_id
    }

    // ===== Register Enclave Pubkey =====
    public fun register_enclave(
        vault: &mut VaultConfig,
        enclave_pubkey: vector<u8>,
        enclave_wasm_double_hash: vector<u8>,
        ctx: &TxContext,
    ) {
        assert!(vault.owner == ctx.sender(), EUnauthorized);
        assert!(enclave_wasm_double_hash == vault.wasm_double_hash, EWrongCircuit);
        assert!(
            !vector::contains(&vault.registered_enclave_pubkeys, &enclave_pubkey),
            EDuplicateEnclave
        );
        assert!(vector::length(&enclave_pubkey) == 32, EUnauthorized);

        vector::push_back(&mut vault.registered_enclave_pubkeys, enclave_pubkey);

        event::emit(EnclaveRegistered {
            vault_id: object::id(vault),
            enclave_pubkey,
        });
    }

    // ===== Unregister Enclave =====
    public fun unregister_enclave(
        vault: &mut VaultConfig,
        enclave_pubkey: vector<u8>,
        ctx: &TxContext,
    ) {
        assert!(vault.owner == ctx.sender(), EUnauthorized);
        let (found, idx) = vector::index_of(&vault.registered_enclave_pubkeys, &enclave_pubkey);
        if (found) {
            vector::remove(&mut vault.registered_enclave_pubkeys, idx);
            event::emit(EnclaveUnregistered {
                vault_id: object::id(vault),
                enclave_pubkey,
            });
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

    // ===== Submit Proof (Core) =====
    //
    // Verifies:
    // 1. Vault not paused
    // 2. Enclave pubkey registered
    // 3. Ed25519 signature (TEE ephemeral key signs proof||inputs)
    // 4. Public inputs length (4 x 32 = 128 bytes)
    // 5. vault_id_hash matches Poseidon(vault_id)
    // 6. Epoch validity
    // 7. Nullifier not reused
    // 8. Groth16 proof valid
    //
    // Returns VaultProof Sui object to caller.
    public fun submit_proof(
        vault: &mut VaultConfig,
        enclave_pubkey: vector<u8>,
        groth16_proof_bytes: vector<u8>,
        public_inputs_bytes: vector<u8>,
        tee_signature: vector<u8>,
        ctx: &mut TxContext,
    ): VaultProof {
        // 1. Not paused
        assert!(!vault.paused, EVaultPaused);

        // 2. Enclave registered
        assert!(
            vector::contains(&vault.registered_enclave_pubkeys, &enclave_pubkey),
            EEnclaveNotRegistered
        );

        // 3. Ed25519 signature: message = proof_bytes || inputs_bytes
        let mut message = groth16_proof_bytes;
        vector::append(&mut message, public_inputs_bytes);
        assert!(
            ed25519::ed25519_verify(&tee_signature, &enclave_pubkey, &message),
            EInvalidTEESignature
        );

        // 4. Public inputs length (4 field elements = 128 bytes)
        assert!(vector::length(&public_inputs_bytes) == 128, EInvalidPublicInputLength);

        // 5. Parse 4 public inputs
        let nullifier = abyssal_types::extract_bytes(&public_inputs_bytes, 0, 32);
        let result_commitment = abyssal_types::extract_bytes(&public_inputs_bytes, 32, 32);
        let vault_id_hash = abyssal_types::extract_bytes(&public_inputs_bytes, 64, 32);
        let expiry_epoch_bytes = abyssal_types::extract_bytes(&public_inputs_bytes, 96, 32);
        let expiry_epoch = abyssal_types::le_bytes_to_u64(expiry_epoch_bytes);

        // 6. Verify vault_id_hash = Poseidon(vault_id_as_field_element)
        // Reduce vault_id modulo BN254 scalar field order (Circom does this implicitly)
        let vault_id_bytes = object::id_to_bytes(&object::id(vault));
        let vault_id_u256 = abyssal_types::bytes32_to_u256(vault_id_bytes) % BN254_R;
        let expected_hash_u256 = poseidon::poseidon_bn254(&vector[vault_id_u256]);
        let expected_hash = abyssal_types::u256_to_bytes32(expected_hash_u256);
        assert!(vault_id_hash == expected_hash, EInvalidVaultIdHash);

        // 7. Epoch validity
        let current_epoch = ctx.epoch();
        assert!(current_epoch <= expiry_epoch, EProofExpired);
        assert!(
            expiry_epoch <= current_epoch + vault.proof_validity_epochs,
            EEpochOutOfRange
        );

        // 8. Nullifier check
        if (vault.nullifier_policy == 0 || vault.nullifier_policy == 1) {
            assert!(
                !table::contains(&vault.used_nullifiers, nullifier),
                ENullifierUsed
            );
            table::add(&mut vault.used_nullifiers, nullifier, true);
        };

        // 9. Groth16 verification
        let curve = groth16::bn254();
        let proof_points = groth16::proof_points_from_bytes(groth16_proof_bytes);
        let public_proof_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);
        assert!(
            groth16::verify_groth16_proof(&curve, &vault.pvk, &public_proof_inputs, &proof_points),
            EInvalidProof
        );

        // 10. Build VaultProof
        let proof_obj = VaultProof {
            id: object::new(ctx),
            vault_id: object::id(vault),
            nullifier,
            result_commitment,
            vault_id_hash,
            expiry_epoch,
            proof_bytes: groth16_proof_bytes,
            public_inputs_bytes,
            enclave_pubkey,
        };

        event::emit(ProofSubmitted {
            vault_id: object::id(vault),
            proof_id: object::id(&proof_obj),
            nullifier,
            expiry_epoch,
        });

        proof_obj
    }

    // ===== Verify VaultProof (non-consuming, for third-party protocols) =====
    public fun verify_vault_proof(
        vault: &VaultConfig,
        proof: &VaultProof,
        ctx: &TxContext,
    ): bool {
        if (proof.vault_id != object::id(vault)) return false;
        ctx.epoch() <= proof.expiry_epoch
    }

    // ===== Consume VaultProof (reveal result, one-time, object destroyed) =====
    public fun consume_proof_with_result(
        vault: &VaultConfig,
        proof: VaultProof,
        result_value_bytes: vector<u8>,
        result_salt_bytes: vector<u8>,
        ctx: &mut TxContext,
    ): vector<u8> {
        assert!(verify_vault_proof(vault, &proof, ctx), EProofExpired);

        // Verify result_commitment = Poseidon(result_value, result_salt)
        let rv_u256 = abyssal_types::bytes32_to_u256(result_value_bytes);
        let rs_u256 = abyssal_types::bytes32_to_u256(result_salt_bytes);
        let computed_u256 = poseidon::poseidon_bn254(&vector[rv_u256, rs_u256]);
        let computed_bytes = abyssal_types::u256_to_bytes32(computed_u256);
        assert!(computed_bytes == proof.result_commitment, EInvalidProof);

        event::emit(ProofConsumed {
            vault_id: proof.vault_id,
            proof_id: object::id(&proof),
            consumer: ctx.sender(),
        });

        let result = result_value_bytes;

        // Destroy VaultProof
        let VaultProof {
            id, vault_id: _, nullifier: _, result_commitment: _,
            vault_id_hash: _, expiry_epoch: _, proof_bytes: _,
            public_inputs_bytes: _, enclave_pubkey: _,
        } = proof;
        object::delete(id);

        result
    }

    // ===== View functions =====
    public fun vault_owner(vault: &VaultConfig): address { vault.owner }
    public fun vault_paused(vault: &VaultConfig): bool { vault.paused }
    public fun vault_wasm_double_hash(vault: &VaultConfig): vector<u8> { vault.wasm_double_hash }
    public fun vault_seal_policy_id(vault: &VaultConfig): ID { vault.seal_policy_id }
    public fun is_enclave_registered(vault: &VaultConfig, pubkey: &vector<u8>): bool {
        vector::contains(&vault.registered_enclave_pubkeys, pubkey)
    }
    public fun proof_vault_id(proof: &VaultProof): ID { proof.vault_id }
    public fun proof_nullifier(proof: &VaultProof): vector<u8> { proof.nullifier }
    public fun proof_result_commitment(proof: &VaultProof): vector<u8> { proof.result_commitment }
    public fun proof_expiry_epoch(proof: &VaultProof): u64 { proof.expiry_epoch }
}
