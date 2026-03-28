# Abyssal — CLAUDE.md

**Canonical spec:** `docs/ABYSSAL_SPEC_v2.1.1.md` — read before making any
design decision. This file only contains gotchas and quick reference.

**Project:** First Web3 PFE (Private Function Evaluation) protocol.
Encrypts Groth16 pk+wasm with Seal IBE, generates proofs inside Nautilus TEE,
puts pvk on-chain. Part of SuiCryptoLib (ARZER-TW).

---

## Layout
```
move/abyssal/sources/          # abyssal_registry (VaultConfig + VaultProof + events),
                               # abyssal_types (byte conversion helpers)
move/abyssal-seal-policy/      # seal_approve for TEE access (depends on abyssal)
move/abyssal-audit-policy/     # seal_approve + AuditAllowlist for auditors
circuits/credit_score/         # Demo VECS-compliant circuit (819 constraints)
tee/abyssal-prover/            # Nautilus TEE Rust server (planned)
sdk/src/                       # TypeScript SDK (planned)
docs/SPEC.md                   # CANONICAL SPEC v2.1.1
```

## Testnet Deployment (2026-03-27)
```
abyssal:             0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777
abyssal-seal-policy: 0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8
abyssal-audit-policy:0xc854ea999c3c3008e0dd978caadb6af4e5c0b8c33dc8197bce2709ed95ea00cf
Deployer:            0x10d607a8db16ad791595e1010a5c97f5eb8578852599ff5b8c22f37a40ebc61b
```

NOTE: Sui requires event structs in the same module as event::emit.
Events and VaultProof stay in abyssal_registry (not separate modules).
SPEC section 6.6 abyssal_events is aspirational; Sui does not support it.

---

## Critical Gotchas — Read Every Time

### 1. Epoch in Move = ctx.epoch(), NOT Clock
```move
// ✅
let epoch = ctx.epoch();

// ❌ clock has NO epoch() method — it does not exist
let epoch = clock::epoch(clock);
```

`Clock` only has `clock::timestamp_ms(clock)`.
- `submit_proof` — no Clock param, uses ctx.epoch()
- `verify_vault_proof` — no Clock param, uses ctx.epoch()
- `consume_proof_with_result` — no Clock param, uses ctx.epoch()
- `seal_approve` — YES Clock param, for timestamp_ms anti-replay only

### 2. Poseidon in Move = poseidon_bn254, no poseidon_N variants
```move
// ✅
poseidon::poseidon_bn254(&vector[a_u256, b_u256])

// ❌ these do not exist
poseidon::poseidon_1(x)
poseidon::poseidon_2(x, y)
```

Circom `Poseidon(N)` component syntax is fine and unchanged.

### 3. pvk = pvk_from_bytes, NOT prepare_verifying_key on-chain
```move
// ✅ low gas — 4 components pre-computed off-chain by SDK
let pvk = groth16::pvk_from_bytes(gamma_abc, alpha_beta, gamma_neg, delta_neg);

// ❌ high gas — never call this on-chain
groth16::prepare_verifying_key(&groth16::bn254(), &raw_vk_bytes);
```

### 4. PCR = 48 bytes (SHA-384), not 32

Each of PCR0/1/2 from AWS Nitro = 48 bytes. All comparisons fail if 32-byte.

### 5. submit_proof takes tee_signature, NOT attestation bytes

Attestation verified ONCE at TEE registration (high gas).
Per-proof: only `tee_signature: vector<u8>` (64 bytes Ed25519).
Message signed = `proof_bytes || public_inputs_bytes`.

### 6. Two completely separate epoch systems

| | Unit | Duration | Used for |
|---|---|---|---|
| Sui epoch | epoch | ~24h | proof_validity_epochs, ctx.epoch() |
| Walrus epoch | epoch | 2 weeks | blob storage walrus_epochs |

`proof_validity_epochs = 28` → ~28 days.
`walrus_epochs = 52` → ~2 years of blob storage.
Never assign one to the other.

### 7. seal_approve must NOT mutate state

Called via `dry_run_transaction_block` by Seal key server.
Any state mutation = silent failure. Entry fun, read-only.
First param must be `id: vector<u8>`. Abyssal uses `id == vector[0u8]`.

### 8. Public inputs = exactly 128 bytes (4 × 32 LE field elements)

Order: `nullifier | result_commitment | vault_id_hash | expiry_epoch`
Always assert `vector::length(&public_inputs_bytes) == 128`.
Groth16 max public inputs = 8. VECS uses 4.

### 9. vault_id must be reduced modulo BN254_R before Poseidon

Sui object IDs are 32-byte hashes. As u256, they can exceed BN254 scalar field
order. `poseidon_bn254` aborts if input >= BN254_R. Both contract and circuit
must reduce: `vault_id_field = vault_id_u256 % BN254_R`. Circom does this
implicitly; Move must do it explicitly.

### 10. vault_id hex is big-endian, bytes32_to_u256 is little-endian

Sui displays object IDs as big-endian hex (`0xe2d4...10`).
Move `bytes32_to_u256` treats bytes[0] as LSB (little-endian).
SDK/frontend MUST reverse byte order when computing vault_id_field:
```javascript
// WRONG: BigInt("0x" + vaultIdHex)  -- big-endian interpretation
// RIGHT: LE interpretation matching Move bytes32_to_u256
const bytes = Buffer.from(vaultIdHex, "hex");
let u256 = 0n;
for (let i = 0; i < 32; i++) u256 |= BigInt(bytes[i]) << BigInt(i * 8);
```

### 11. pk AND wasm must both be encrypted

wasm is compiled from circuit — reverse-engineerable without encryption.
Both go to Walrus via Seal IBE. pk uses VaultKeyPolicy. wasm uses VaultKeyPolicy.
Circuit source uses AuditAllowlistPolicy (different package).

---

### 12. @mysten/seal decrypt() = full 2-phase key load internally

Seal SDK `sealClient.decrypt()` internally does:
1. `SessionKey.createRequestParams()` — generates BLS12-381 ElGamal keypair
2. `fetchKeysForAllIds()` — POST `/v1/fetch_key` to key servers
3. `elgamalDecrypt()` — BLS G1 point arithmetic to decrypt responses
4. AES-256-GCM decrypt the final plaintext

For Node.js TEE mock (has network), use `sealClient.decrypt()` directly.
For production Nitro Enclave (no network), need 2-phase split via Seal CLI.

### 13. @mysten/sui v2.x breaking changes

v2 renamed core client: `SuiClient` -> `SuiJsonRpcClient` (from `@mysten/sui/jsonRpc`).
`getFullnodeUrl` -> `getJsonRpcFullnodeUrl`. The root project uses v2 (@mysten/seal requires it).
SDK subdir still uses v1 — will need migration when updating.

### 14. Walrus testnet aggregator for blob download

```
GET https://aggregator.walrus-testnet.walrus.space/v1/blobs/<blob-id>
```
Epoch duration: 1 day (testnet), 14 days (mainnet). Max 53 epochs.

---

## Key External Docs

- Sui Groth16: https://docs.sui.io/guides/developer/cryptography/groth16
- Nautilus design: https://docs.sui.io/guides/developer/nautilus/nautilus-design
- Nautilus + Seal: https://docs.sui.io/guides/developer/nautilus/seal
- Seal usage: https://seal-docs.wal.app/UsingSeal
- Walrus: https://docs.wal.app/

**MCP tool available:** Use `mcp__sui-knowledge-docs__search_sui_knowledge_sources`
to query Sui official docs in real-time. Always prefer this over cached knowledge
for Sui Move APIs, Seal SDK, Walrus CLI, and Nautilus interfaces.

## Predecessor Project

SuiCryptoLib at `/home/james/projects/suicryptolib/` is the engineering foundation.
Key reusable assets:
- `circuits/poc/format_for_sui.mjs` — snarkjs-to-Sui Arkworks format conversion (G1/G2 compression, LE byte order, y-sign bit)
- `circuits/pot13.ptau`, `circuits/pot15.ptau` — Powers of Tau ceremony files
- `sdk/src/` — ESM + circomlibjs patterns for SDK scaffold
- `move/sources/groth16_poc.move` — Groth16 bridge pattern reference (but Abyssal uses pvk_from_bytes, not prepare_verifying_key)
