/// Abyssal Seal Policy — TEE key access control.
///
/// Called by Seal key server via dry_run_transaction_block (read-only).
/// Verifies that the requesting TEE enclave is registered with the vault
/// and that the request is fresh (timestamp anti-replay).
///
/// Hackathon version: uses enclave_pubkey directly instead of Nautilus Enclave object.
/// Production version: replace enclave_pubkey with &nautilus_enclave::Enclave reference.
module abyssal_seal_policy::abyssal_seal_policy {
    use sui::clock::{Self, Clock};
    use sui::ed25519;
    use sui::bcs;
    use abyssal::abyssal_registry::VaultConfig;
    use abyssal::abyssal_registry;

    const ENoAccess: u64 = 0;

    /// Seal calls this via dry_run_transaction_block.
    /// Must NOT mutate any state (dry_run is read-only).
    ///
    /// Params:
    ///   id             — IBE identity inner bytes (must be vector[0u8] for Abyssal)
    ///   vault_config   — the VaultConfig shared object
    ///   enclave_pubkey — 32-byte Ed25519 pubkey of requesting TEE
    ///   wallet_pubkey  — 32-byte Ed25519 pubkey of Seal wallet (TEE-generated)
    ///   timestamp      — current timestamp in ms (for anti-replay)
    ///   sig            — Ed25519 signature by enclave ephemeral key over (wallet_pubkey || timestamp_bcs)
    ///   clock          — Sui Clock for timestamp_ms verification
    entry fun seal_approve(
        id: vector<u8>,
        vault_config: &VaultConfig,
        enclave_pubkey: vector<u8>,
        wallet_pubkey: vector<u8>,
        timestamp: u64,
        sig: vector<u8>,
        clock: &Clock,
    ) {
        // 1. IBE identity must be the fixed value vector[0u8]
        assert!(id == vector[0u8], ENoAccess);

        // 2. Enclave must be registered with this vault
        assert!(
            abyssal_registry::is_enclave_registered(vault_config, &enclave_pubkey),
            ENoAccess
        );

        // 3. Timestamp within 60-second window (anti-replay)
        let current_time_ms = clock::timestamp_ms(clock);
        assert!(timestamp <= current_time_ms + 60_000, ENoAccess);
        assert!(current_time_ms <= timestamp + 60_000, ENoAccess);

        // 4. Verify Ed25519 signature: enclave ephemeral key signs (wallet_pubkey || timestamp_bcs)
        let mut message = wallet_pubkey;
        vector::append(&mut message, bcs::to_bytes(&timestamp));
        assert!(
            ed25519::ed25519_verify(&sig, &enclave_pubkey, &message),
            ENoAccess
        );
    }
}
