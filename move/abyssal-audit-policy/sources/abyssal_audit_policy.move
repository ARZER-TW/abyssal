/// Abyssal Audit Policy — Designated auditor access control for circuit source.
///
/// Separate from VaultKeyPolicy. Controls who can decrypt the circuit source
/// blob on Walrus (for independent code audit).
///
/// AuditAllowlist is a shared object per vault, managed by vault owner.
/// seal_approve verifies the caller is on the allowlist.
module abyssal_audit_policy::abyssal_audit_policy {
    use sui::clock::{Self, Clock};
    use sui::event;

    const ENoAccess: u64 = 0;
    const EUnauthorized: u64 = 1;
    const EDuplicateAuditor: u64 = 2;

    // ===== AuditAllowlist (shared object, one per vault) =====
    public struct AuditAllowlist has key {
        id: UID,
        vault_id: ID,
        authorized_auditors: vector<address>,
        owner: address,
    }

    // ===== Events =====
    public struct AuditAccess has copy, drop {
        vault_id: ID,
        auditor: address,
        timestamp_ms: u64,
    }

    public struct AllowlistCreated has copy, drop {
        allowlist_id: ID,
        vault_id: ID,
        owner: address,
    }

    public struct AuditorAdded has copy, drop {
        allowlist_id: ID,
        auditor: address,
    }

    public struct AuditorRemoved has copy, drop {
        allowlist_id: ID,
        auditor: address,
    }

    // ===== Create Allowlist =====
    public fun create_allowlist(
        vault_id: ID,
        ctx: &mut TxContext,
    ): ID {
        let allowlist = AuditAllowlist {
            id: object::new(ctx),
            vault_id,
            authorized_auditors: vector::empty(),
            owner: ctx.sender(),
        };
        let allowlist_id = object::id(&allowlist);

        event::emit(AllowlistCreated {
            allowlist_id,
            vault_id,
            owner: ctx.sender(),
        });

        transfer::share_object(allowlist);
        allowlist_id
    }

    // ===== Add Auditor =====
    public fun add_auditor(
        allowlist: &mut AuditAllowlist,
        auditor: address,
        ctx: &TxContext,
    ) {
        assert!(allowlist.owner == ctx.sender(), EUnauthorized);
        assert!(
            !vector::contains(&allowlist.authorized_auditors, &auditor),
            EDuplicateAuditor
        );
        vector::push_back(&mut allowlist.authorized_auditors, auditor);

        event::emit(AuditorAdded {
            allowlist_id: object::id(allowlist),
            auditor,
        });
    }

    // ===== Remove Auditor =====
    public fun remove_auditor(
        allowlist: &mut AuditAllowlist,
        auditor: address,
        ctx: &TxContext,
    ) {
        assert!(allowlist.owner == ctx.sender(), EUnauthorized);
        let (found, idx) = vector::index_of(&allowlist.authorized_auditors, &auditor);
        if (found) {
            vector::remove(&mut allowlist.authorized_auditors, idx);
            event::emit(AuditorRemoved {
                allowlist_id: object::id(allowlist),
                auditor,
            });
        };
    }

    // ===== Seal Approve (called via dry_run, read-only) =====
    /// Verifies the transaction sender is an authorized auditor.
    /// Emits AuditAccess event for audit trail.
    ///
    /// NOTE: event::emit in dry_run does NOT persist on-chain,
    /// but the event is visible in the dry_run response for logging.
    entry fun seal_approve(
        id: vector<u8>,
        allowlist: &AuditAllowlist,
        clock: &Clock,
        ctx: &TxContext,
    ) {
        // IBE identity must be vector[0u8]
        assert!(id == vector[0u8], ENoAccess);

        // Caller must be an authorized auditor
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

    // ===== View Functions =====
    public fun allowlist_vault_id(allowlist: &AuditAllowlist): ID { allowlist.vault_id }
    public fun allowlist_owner(allowlist: &AuditAllowlist): address { allowlist.owner }
    public fun is_authorized_auditor(allowlist: &AuditAllowlist, addr: &address): bool {
        vector::contains(&allowlist.authorized_auditors, addr)
    }
}
