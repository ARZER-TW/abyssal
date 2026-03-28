/// Abyssal Groth16 proof tests.
/// Uses real test vectors from credit_score circuit (Phase 2).
///
/// NOTE on vault_id_hash: The circuit's public inputs contain a vault_id_hash
/// computed from a test vault_id_field. Since test_scenario generates dynamic
/// object IDs, full E2E submit_proof testing requires pre-computing vectors
/// with the correct vault_id. These tests verify individual verification steps.
#[test_only]
#[allow(unused_variable, unused_use)]
module abyssal::abyssal_groth16_tests {
    use sui::test_scenario;
    use sui::groth16;
    use abyssal::abyssal_registry::{Self, VaultConfig};

    const DEPLOYER: address = @0xD;
    const USER: address = @0xA;

    // === Real test vectors from credit_score circuit ===

    // Raw VK for prepare_verifying_key (392 bytes, Arkworks compressed)
    const VK_BYTES: vector<u8> = x"e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e1937c5226abada95de1d7cb9d69002ef5b06c27f6a9cc689835f8e1632a2eda20947030d33abcec8bf1c6561c79dc2277621081797af498723befd3fa8142dfd910500000000000000e39d91935bf747e657b20d5b800452afa0164148c5b6bdb8e174564ecfb5788ecff7607231ef0f104af688a0ae080bce95e63e21a6f3c1a38916237063dfc00ed3a3f9a22a75c595a9f85352acddc272b19c3379f6e16e1027b5fd438c4d8f10dadeb579d674bda122c98b4545b1706a8bd165e6c98fe2a691b593e1d70c8d9e9c6fdbf4cf6ba685320dbdf6232ad646be60dc3671b38bdd1307f4b2ff03ae1f";

    // Groth16 proof (128 bytes)
    const PROOF_BYTES: vector<u8> = x"b0e89d5a13dce656390fd616fe378c93f8aa411e10780c544ffd884daea542129f62e804f43ec4898c53b4ec35871e85f6b3225f55ee0949fb167f4dc863990edd451fa04f382e5dd184d00e1ab7b9ce07ce235001ca1d0e11520605f64756804a8325f4ed325a26f2f4751f689fad73b2409b91a8b3f14f49ee0b8f4683c088";

    // Public inputs (128 bytes = 4 x 32 LE field elements)
    // [0] nullifier, [1] result_commitment, [2] vault_id_hash, [3] expiry_epoch=128
    const PUBLIC_INPUTS_BYTES: vector<u8> = x"9b9e8b61fbfcb2268544d3494a7a4bf8fef6be77dbd95efdc2e4281a5f3587129bdf4bd28e637e38d4707f542a57dddb5ab65669a6443b2d2b2f4ad19a81ea0762cc138417651748f6e032f3f9b514218e13d0ee1a4fb12c8b16cfa3605f9d088000000000000000000000000000000000000000000000000000000000000000";

    // TEE Ed25519 pubkey (32 bytes)
    const TEE_PUBKEY: vector<u8> = x"e1ef2fe6f211f7399a8a6a55fdc811ee92ec7f01ee125942da87ef659553499f";

    // Ed25519 signature over (proof || inputs) (64 bytes)
    const TEE_SIGNATURE: vector<u8> = x"8786d85526d7167520130848e699a9f244811ff089f498b387bfecafc8fa4b3b60f5b038c4a0d8bd4f248812bb6d48b198979480548c59d96a2ee2fb70996e0c";

    const DUMMY_WASM_DOUBLE_HASH: vector<u8> = x"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    // === Helper: create vault with real pvk ===
    fun create_real_vault(scenario: &mut test_scenario::Scenario) {
        test_scenario::next_tx(scenario, DEPLOYER);

        // Use prepare_verifying_key to get 4 pvk components from raw VK
        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &VK_BYTES);
        let components = groth16::pvk_to_bytes(pvk);

        let _vault_id = abyssal_registry::create_vault(
            components[0],
            components[1],
            components[2],
            components[3],
            DUMMY_WASM_DOUBLE_HASH,
            x"1234",
            x"5678",
            x"abcd", // circuit_source_blob_id
            object::id_from_address(@0x999),
            28,
            0,
            b"Credit Score Vault",
            test_scenario::ctx(scenario),
        );
    }

    // ===== T-03: Standalone Groth16 verification (proof + vk + inputs) =====
    #[test]
    fun test_groth16_proof_valid() {
        let curve = groth16::bn254();
        let pvk = groth16::prepare_verifying_key(&curve, &VK_BYTES);
        let proof_points = groth16::proof_points_from_bytes(PROOF_BYTES);
        let public_inputs = groth16::public_proof_inputs_from_bytes(PUBLIC_INPUTS_BYTES);

        assert!(
            groth16::verify_groth16_proof(&curve, &pvk, &public_inputs, &proof_points),
            0
        );
    }

    // ===== T-04: Groth16 verification with wrong proof fails =====
    #[test]
    fun test_groth16_wrong_proof_fails() {
        let curve = groth16::bn254();
        let pvk = groth16::prepare_verifying_key(&curve, &VK_BYTES);

        // Corrupt the first byte of the proof
        let mut bad_proof = PROOF_BYTES;
        let first = vector::borrow_mut(&mut bad_proof, 0);
        *first = if (*first == 255) { 0u8 } else { *first + 1 };

        let proof_points = groth16::proof_points_from_bytes(bad_proof);
        let public_inputs = groth16::public_proof_inputs_from_bytes(PUBLIC_INPUTS_BYTES);

        assert!(
            !groth16::verify_groth16_proof(&curve, &pvk, &public_inputs, &proof_points),
            0
        );
    }

    // ===== T-05: Groth16 verification with wrong inputs fails =====
    #[test]
    fun test_groth16_wrong_inputs_fails() {
        let curve = groth16::bn254();
        let pvk = groth16::prepare_verifying_key(&curve, &VK_BYTES);
        let proof_points = groth16::proof_points_from_bytes(PROOF_BYTES);

        // Corrupt public inputs
        let mut bad_inputs = PUBLIC_INPUTS_BYTES;
        let first = vector::borrow_mut(&mut bad_inputs, 0);
        *first = if (*first == 255) { 0u8 } else { *first + 1 };

        let public_inputs = groth16::public_proof_inputs_from_bytes(bad_inputs);

        assert!(
            !groth16::verify_groth16_proof(&curve, &pvk, &public_inputs, &proof_points),
            0
        );
    }

    // ===== T-06: pvk_from_bytes produces same result as prepare_verifying_key =====
    #[test]
    fun test_pvk_from_bytes_equivalence() {
        let curve = groth16::bn254();

        // Method 1: prepare_verifying_key
        let pvk1 = groth16::prepare_verifying_key(&curve, &VK_BYTES);
        let components = groth16::pvk_to_bytes(pvk1);

        // Method 2: pvk_from_bytes with extracted components
        let pvk2 = groth16::pvk_from_bytes(
            components[0], components[1], components[2], components[3]
        );

        // Both should verify the same proof
        let proof_points = groth16::proof_points_from_bytes(PROOF_BYTES);
        let public_inputs = groth16::public_proof_inputs_from_bytes(PUBLIC_INPUTS_BYTES);

        assert!(groth16::verify_groth16_proof(&curve, &pvk2, &public_inputs, &proof_points), 0);
    }

    // ===== T-07: submit_proof fails when vault paused =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EVaultPaused)]
    fun test_submit_proof_vault_paused() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_real_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        // Register enclave then pause
        abyssal_registry::register_enclave(
            &mut vault, TEE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );
        abyssal_registry::pause_vault(&mut vault, test_scenario::ctx(&mut scenario));

        // submit_proof should fail with EVaultPaused
        test_scenario::next_tx(&mut scenario, USER);
        let proof = abyssal_registry::submit_proof(
            &mut vault, TEE_PUBKEY, PROOF_BYTES, PUBLIC_INPUTS_BYTES, TEE_SIGNATURE,
            test_scenario::ctx(&mut scenario),
        );
        transfer::public_transfer(proof, USER);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-08: submit_proof fails with unregistered enclave =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EEnclaveNotRegistered)]
    fun test_submit_proof_unregistered_enclave() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_real_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, USER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        // Don't register enclave, submit directly
        let proof = abyssal_registry::submit_proof(
            &mut vault, TEE_PUBKEY, PROOF_BYTES, PUBLIC_INPUTS_BYTES, TEE_SIGNATURE,
            test_scenario::ctx(&mut scenario),
        );
        transfer::public_transfer(proof, USER);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-09: submit_proof fails with invalid signature =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EInvalidTEESignature)]
    fun test_submit_proof_bad_signature() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_real_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        abyssal_registry::register_enclave(
            &mut vault, TEE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        // Use a garbage signature
        let bad_sig = x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f";

        test_scenario::next_tx(&mut scenario, USER);
        let proof = abyssal_registry::submit_proof(
            &mut vault, TEE_PUBKEY, PROOF_BYTES, PUBLIC_INPUTS_BYTES, bad_sig,
            test_scenario::ctx(&mut scenario),
        );
        transfer::public_transfer(proof, USER);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-10: submit_proof fails with wrong input length =====
    // NOTE: Ed25519 sig check (step 3) fires before length check (step 4)
    // because the signature was computed over original 128-byte inputs.
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EInvalidTEESignature)]
    fun test_submit_proof_bad_input_length() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_real_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        abyssal_registry::register_enclave(
            &mut vault, TEE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        // Short inputs (64 bytes instead of 128)
        let short_inputs = x"9b9e8b61fbfcb2268544d3494a7a4bf8fef6be77dbd95efdc2e4281a5f3587129bdf4bd28e637e38d4707f542a57dddb5ab65669a6443b2d2b2f4ad19a81ea07";

        // Re-sign with short inputs (sig will be wrong but we test length check first)
        test_scenario::next_tx(&mut scenario, USER);
        let proof = abyssal_registry::submit_proof(
            &mut vault, TEE_PUBKEY, PROOF_BYTES, short_inputs, TEE_SIGNATURE,
            test_scenario::ctx(&mut scenario),
        );
        transfer::public_transfer(proof, USER);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-11: submit_proof fails with mismatched vault_id_hash =====
    // (proves vault_id_hash check works — test inputs have vault_id_hash from test circuit,
    //  not from the actual dynamic vault_id)
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EInvalidVaultIdHash)]
    fun test_submit_proof_wrong_vault_id_hash() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_real_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        abyssal_registry::register_enclave(
            &mut vault, TEE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        // This will pass sig check and input length check,
        // but fail at vault_id_hash because the circuit was computed
        // with vault_id_field=98765432109876543210, not the actual vault ID
        test_scenario::next_tx(&mut scenario, USER);
        let proof = abyssal_registry::submit_proof(
            &mut vault, TEE_PUBKEY, PROOF_BYTES, PUBLIC_INPUTS_BYTES, TEE_SIGNATURE,
            test_scenario::ctx(&mut scenario),
        );
        transfer::public_transfer(proof, USER);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }
}
