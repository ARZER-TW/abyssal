/// Abyssal registry unit tests.
/// Tests that require real Groth16 proofs are marked with _TODO_PROOF suffix
/// and will be completed after Phase 2 (VECS circuit) provides test vectors.
#[test_only]
module abyssal::abyssal_registry_tests {
    use sui::test_scenario;
    use abyssal::abyssal_registry::{Self, VaultConfig, VaultProof};

    const DEPLOYER: address = @0xD;
    const USER: address = @0xA;
    const OTHER: address = @0xB;

    // Dummy pvk components (not a real VK, but structurally valid for create_vault)
    // Real VK will come from Phase 2 circuit
    const DUMMY_VK_GAMMA: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    const DUMMY_ALPHA_BETA: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    const DUMMY_GAMMA_NEG: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    const DUMMY_DELTA_NEG: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";

    const DUMMY_WASM_DOUBLE_HASH: vector<u8> = x"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const DUMMY_PK_BLOB: vector<u8> = x"1234";
    const DUMMY_WASM_BLOB: vector<u8> = x"5678";
    const DUMMY_ENCLAVE_PUBKEY: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const WRONG_WASM_HASH: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";

    // Helper: create a vault in a test scenario
    fun create_test_vault(scenario: &mut test_scenario::Scenario) {
        test_scenario::next_tx(scenario, DEPLOYER);
        let ctx = test_scenario::ctx(scenario);

        let _vault_id = abyssal_registry::create_vault(
            DUMMY_VK_GAMMA,
            DUMMY_ALPHA_BETA,
            DUMMY_GAMMA_NEG,
            DUMMY_DELTA_NEG,
            DUMMY_WASM_DOUBLE_HASH,
            DUMMY_PK_BLOB,
            DUMMY_WASM_BLOB,
            x"abcd", // dummy circuit_source_blob_id
            object::id_from_address(@0x999), // dummy seal policy ID
            28, // ~28 days validity
            0,  // one-time nullifier
            b"Test Vault",
            ctx,
        );
    }

    // ===== T-01: create_vault valid =====
    #[test]
    fun test_create_vault_valid() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let vault = test_scenario::take_shared<VaultConfig>(&scenario);

        assert!(abyssal_registry::vault_owner(&vault) == DEPLOYER, 0);
        assert!(!abyssal_registry::vault_paused(&vault), 1);
        assert!(abyssal_registry::vault_wasm_double_hash(&vault) == DUMMY_WASM_DOUBLE_HASH, 2);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-20: register_enclave wrong wasm_hash =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EWrongCircuit)]
    fun test_register_enclave_wrong_wasm_hash() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        abyssal_registry::register_enclave(
            &mut vault,
            DUMMY_ENCLAVE_PUBKEY,
            WRONG_WASM_HASH, // wrong hash
            test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-21: register_enclave duplicate rejected =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EDuplicateEnclave)]
    fun test_register_enclave_duplicate_rejected() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        // First registration
        abyssal_registry::register_enclave(
            &mut vault, DUMMY_ENCLAVE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        // Second registration of same pubkey
        abyssal_registry::register_enclave(
            &mut vault, DUMMY_ENCLAVE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-22: unregister_enclave =====
    #[test]
    fun test_unregister_enclave() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        // Register then unregister
        abyssal_registry::register_enclave(
            &mut vault, DUMMY_ENCLAVE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        abyssal_registry::unregister_enclave(
            &mut vault, DUMMY_ENCLAVE_PUBKEY,
            test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-23: unauthorized vault operations =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EUnauthorized)]
    fun test_unauthorized_register_enclave() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        // OTHER tries to register (not owner)
        test_scenario::next_tx(&mut scenario, OTHER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        abyssal_registry::register_enclave(
            &mut vault, DUMMY_ENCLAVE_PUBKEY, DUMMY_WASM_DOUBLE_HASH,
            test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-18: vault pause rejects proof submission =====
    #[test]
    fun test_vault_pause_resume() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, DEPLOYER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        // Pause
        abyssal_registry::pause_vault(&mut vault, test_scenario::ctx(&mut scenario));
        assert!(abyssal_registry::vault_paused(&vault), 0);

        // Resume
        abyssal_registry::resume_vault(&mut vault, test_scenario::ctx(&mut scenario));
        assert!(!abyssal_registry::vault_paused(&vault), 1);

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }

    // ===== T-23b: unauthorized pause =====
    #[test]
    #[expected_failure(abort_code = abyssal_registry::EUnauthorized)]
    fun test_unauthorized_pause() {
        let mut scenario = test_scenario::begin(DEPLOYER);
        create_test_vault(&mut scenario);

        test_scenario::next_tx(&mut scenario, OTHER);
        let mut vault = test_scenario::take_shared<VaultConfig>(&scenario);

        abyssal_registry::pause_vault(&mut vault, test_scenario::ctx(&mut scenario));

        test_scenario::return_shared(vault);
        test_scenario::end(scenario);
    }
}
