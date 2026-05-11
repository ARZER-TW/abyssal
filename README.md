# Abyssal

[English](README.md) | [繁體中文](README.zh-Hant.md)

**The first Web3 protocol for Private Function Evaluation (PFE) on Sui.**

Encrypt both the proving key and the witness calculator with Seal IBE, generate Groth16 proofs inside an AWS Nitro Enclave, and publish only the verification key on-chain. Anyone can verify a proof is valid; no one can reverse-engineer what the circuit computes.

- **Status:** Testnet deployed and end-to-end verified
- **Spec:** [`docs/SPEC.md`](docs/SPEC.md) v2.1.1
- **Live demo:** [`demo/index.html`](demo/index.html)
- **Network:** Sui Testnet
- **Move edition:** 2024.beta

---

## The Problem

Cryptography has long conflated two privacy goals:

| | Hidden | Public | Solved by |
|---|---|---|---|
| **Data Privacy** | Input data | Computation logic | Aztec, Aleo, ZK-Rollups, Tornado Cash |
| **Function Privacy (PFE)** | Input data **and** computation logic itself | Result verifiability | **Unsolved on any production blockchain** |

A bank's credit-scoring model, an exchange's risk engine, an insurer's pricing formula — these are decades of accumulated trade secrets. The institutions cannot put them on a public chain (logic leaks instantly) and cannot keep them centralised (users must blindly trust). Today the market routes around this with $100B+/year of "trusted intermediaries": rating agencies, auditors, consultancies.

**Abyssal makes algorithm privacy, trusted results, and verifier independence simultaneously possible.**

---

## The Cryptographic Insight

Groth16's trusted setup produces two keys with fundamentally asymmetric properties:

```
Proving Key (pk) ─── 5-50 MB
  Contains the complete polynomial encoding of circuit logic.
  Required to generate proofs.
  Analysable: reveals what the circuit computes.

Verifying Key (vk → pvk) ─── ~600 bytes
  Sufficient to verify any proof from the corresponding pk.
  Mathematically impossible to reverse-engineer circuit logic from.
```

**On-chain proof verification needs only pvk, never pk.** And the `.wasm` witness calculator is machine code of the circuit — reverse-engineerable.

Abyssal's core construction:

> Encrypt **both** pk and wasm with Seal IBE; allow decryption only by Nautilus enclaves that pass PCR attestation. Publish pvk on-chain. The world can verify; no one can copy.

This has not been done before in any production ZK system.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Deployer ─────► Seal IBE encrypt(pk, wasm, source)            │
│                                  │                              │
│                                  ▼                              │
│                            Walrus blob store                    │
│                                  │                              │
│                                  ▼                              │
│                     ┌─────────────────────────┐                 │
│                     │  Sui Move VaultConfig   │ ◄── pvk on-chain│
│                     │  (shared object)        │                 │
│                     └────────────┬────────────┘                 │
│                                  │                              │
│                                  │ register_enclave             │
│                                  ▼                              │
│   User ─────► Nautilus TEE (AWS Nitro Enclave)                  │
│                  1. Seal decrypts pk + wasm                     │
│                  2. snarkjs generates Groth16 proof             │
│                  3. ed25519 signs (proof || public_inputs)      │
│                                  │                              │
│                                  ▼                              │
│   submit_proof ──► Move 9-step verification ──► VaultProof obj  │
│                                  │                              │
│                                  ▼                              │
│   Third-party protocol consumes VaultProof, gets the result.    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Three actors, no trusted intermediary**:

| Actor | Trust assumption | What they cannot do |
|---|---|---|
| **Deployer** (FinTech / Bank) | Holds toxic waste from Trusted Setup ceremony | Cannot serve different users with different rules — pvk is fixed on-chain |
| **TEE Operator** (AWS Nitro Enclave) | Hardware security boundary | Cannot leak pk/wasm — attestation gates Seal decryption; cannot forge proofs without valid witness |
| **User / Verifier** | None for verification, holds private inputs | Anyone with a Sui node can verify a proof in one transaction |

**Security degradation properties**:

- **If the TEE is compromised:** logic leaks (commercial loss), but **asset safety is unaffected** — an attacker with pk still cannot forge a proof for a user who does not satisfy the constraints. This is Abyssal's fundamental advantage over pure-TEE privacy chains (Secret Network, Phala).
- **If Seal key servers collude beyond threshold:** same as above — logic leaks, asset safety holds.

---

## Live on Testnet

All artifacts are real, on-chain, and verifiable:

| Object | ID | Explorer |
|---|---|---|
| `abyssal` package | `0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777` | [SuiScan](https://suiscan.xyz/testnet/object/0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777) |
| `abyssal-seal-policy` package | `0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8` | [SuiScan](https://suiscan.xyz/testnet/object/0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8) |
| `abyssal-audit-policy` package | `0xc854ea999c3c3008e0dd978caadb6af4e5c0b8c33dc8197bce2709ed95ea00cf` | [SuiScan](https://suiscan.xyz/testnet/object/0xc854ea999c3c3008e0dd978caadb6af4e5c0b8c33dc8197bce2709ed95ea00cf) |
| Example `VaultConfig` (credit score) | `0x921c99ac92b08906b2034c584fdc692cbd132ef8de1c9e87eb03194afc34f084` | [SuiScan](https://suiscan.xyz/testnet/object/0x921c99ac92b08906b2034c584fdc692cbd132ef8de1c9e87eb03194afc34f084) |
| `AuditAllowlist` for that vault | `0x2280b8406afd5e094463090e6165701aa574bd893a1c16d58b9178cd6e2c69bc` | [SuiScan](https://suiscan.xyz/testnet/object/0x2280b8406afd5e094463090e6165701aa574bd893a1c16d58b9178cd6e2c69bc) |

The example vault hosts the encrypted credit-scoring circuit. Its proving key, witness calculator, and circuit source are stored on Walrus testnet:

| Blob | Walrus ID |
|---|---|
| Encrypted `pk` (sealed with VaultKeyPolicy) | `c-k7JX2VUPdkj8qMXOeiFRBaYV_wXcIPJUoURRG6EzU` |
| Encrypted `wasm` (sealed with VaultKeyPolicy) | `zrGm8z8qHVm7_6Ji9O0TlzWDr96xb3yRv2Atn-94MxI` |
| Encrypted circuit source (sealed with AuditAllowlistPolicy) | `NECiydYRxlPQ9PmLP_SUXYQbOWaJH2xd1dUjkr5OL-I` |

`wasm_double_hash` (on-chain circuit identity): `2c64b5bb4dbe2e964f24304a1099028025410f8bbc9c1da4aa7f361434cb2279`

---

## 5-Minute Demo

The canonical demo path is the CLI deployment script — it exercises all three protocols (Seal + Walrus + Nautilus) end-to-end and produces a real on-chain `VaultProof`.

### Prerequisites

- Sui CLI (`sui` testnet build), Walrus CLI (`walrus`)
- Node.js 20+ with `pnpm` or `npm`
- A Sui testnet wallet with ≥ 1 SUI ([faucet](https://docs.sui.io/guides/developer/getting-started/get-coins))
- WAL tokens for Walrus storage

### Run the full pipeline

```bash
# 1. Install dependencies
pnpm install
cd sdk && pnpm install && cd ..
cd tee/abyssal-prover && pnpm install && cd ../..
cd frontend && pnpm install && cd ..

# 2. Compile the demo circuit (Powers of Tau ceremony cached in circuits/)
cd circuits/credit_score
node setup.mjs        # runs the snarkjs groth16 setup
cd ../..

# 3. Start the TEE prover (mock Nitro Enclave for hackathon)
cd tee/abyssal-prover
pnpm start            # listens on :3001
# (leave running in a separate terminal)

# 4. Deploy: seal-encrypt → Walrus upload → on-chain vault → audit allowlist → TEE load → E2E proof
node scripts/deploy_full.mjs
```

Expected output: a new `VaultConfig` shared object, an `AuditAllowlist`, three Walrus blob IDs, an enclave registration, and a `VaultProof` object created by submitting a real Groth16 proof. The script saves all IDs to `scripts/deployment.json`.

### Verify an existing proof

```bash
sui client call \
  --package 0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777 \
  --module abyssal_registry \
  --function verify_vault_proof \
  --args <vault_id> <proof_id>
```

### Independent audit (Layer 1+2 of five-layer chain)

```bash
node scripts/audit_vault.mjs
```

Decrypts the circuit source from Walrus (requires being on the AuditAllowlist), recompiles, and compares `wasm_double_hash` against on-chain state.

---

## Project Structure

```
abyssal/
├── move/
│   ├── abyssal/                    Core: VaultConfig + VaultProof + lifecycle
│   ├── abyssal-seal-policy/        Seal access control for TEE
│   └── abyssal-audit-policy/       Seal access control for auditors
├── circuits/credit_score/          VECS-compliant demo circuit (819 constraints)
├── tee/abyssal-prover/             Node.js TEE server (hackathon mock for Nitro)
├── sdk/                            TypeScript SDK (early stage)
├── frontend/                       React + dApp Kit UI (browse/verify operational)
├── scripts/
│   ├── deploy_full.mjs             Full pipeline: encrypt → store → deploy → register → prove
│   └── audit_vault.mjs             Auditor flow (Layer 1+2)
├── demo/                           Static presentation page
├── docs/SPEC.md                    Canonical specification v2.1.1
└── CLAUDE.md                       Project rules and gotchas
```

---

## Technical Specifications

### VECS — Verifier-Equivalent Circuit Standard

Every Abyssal circuit must expose exactly **4 public inputs in this order** (within Groth16's 8-input ceiling), totalling **128 bytes**:

```
[0..32)    nullifier         = Poseidon(user_secret, vault_id_field, epoch)
[32..64)   result_commitment = Poseidon(result_value, result_salt)
[64..96)   vault_id_hash     = Poseidon(vault_id_field)
[96..128)  expiry_epoch      u64 LE, zero-padded to 32 bytes (BN254 element)
```

All values are BN254 scalar field elements, little-endian encoded. Semantic opacity is enforced: no public input may leak business meaning. See [SPEC §5](docs/SPEC.md).

### `submit_proof` 9-step on-chain verification

1. Vault not paused
2. Enclave public key registered with this vault
3. Ed25519 verify TEE signature on `proof_bytes || public_inputs_bytes`
4. `public_inputs_bytes.length() == 128`
5. Parse 4 inputs at fixed byte offsets
6. `vault_id_hash == Poseidon(vault_id_u256 mod BN254_R)`
7. `current_epoch ≤ expiry_epoch ≤ current_epoch + proof_validity_epochs`
8. Nullifier check per `nullifier_policy`
9. `groth16::verify_groth16_proof` with on-chain `pvk`

See [SPEC §6.4](docs/SPEC.md).

### Cryptographic primitives

| Use | Primitive | Library |
|---|---|---|
| Proof system | Groth16 over BN254 | `sui::groth16` (on-chain), `snarkjs` (TEE) |
| Hash inside circuit | Poseidon-BN254 | `circomlib` (circuit), `sui::poseidon` (on-chain) |
| TEE signature | Ed25519 | `sui::ed25519`, `tweetnacl` |
| Circuit-binding hash | SHA-256 of SHA-256 (`wasm_double_hash`) | `crypto` standard library |
| IBE encryption | Seal threshold IBE | `@mysten/seal` |
| Blob storage | Walrus erasure-coded | `@mysten/walrus`, Walrus CLI |
| TEE attestation (production) | AWS Nitro NSM | `sui::nitro_attestation` |

---

## Trust Model

### Eliminated by Abyssal

- Trust that the institution "hasn't secretly changed the rules" — `pvk` is fixed on-chain; every proof verifies against the same circuit, mathematically.
- Trust that "the same standards apply to all users" — the circuit has no dynamic branches keyed on user identity; the same `pvk` validates all proofs.
- Trust that "user data hasn't leaked" — private inputs never leave the TEE hardware boundary.
- Trust that "audit reports are honest" — designated auditors independently decrypt the circuit source, recompile, and verify `wasm_double_hash` matches.

### Remaining (must be disclosed in all external documentation)

| Assumption | Description | Mitigation |
|---|---|---|
| AWS Nitro Enclave hardware | No backdoor in Nitro Secure Module | Industry-standard TEE assumption; same as all confidential compute |
| Seal key server honesty | Hackathon: 2-of-2 testnet servers. Production: t-of-n DKS | Increase threshold and node count on mainnet |
| TEE source code matches PCR | Reproducible builds; auditors recompile from decrypted source | Provided by the Layer 1+2 audit script |
| Trusted Setup ceremony integrity | Demo uses Powers of Tau + deployer contribution | Production should use a multi-party ceremony |

---

## Hackathon Simplifications

We are explicit about what is hackathon-grade and what production requires:

| Component | Hackathon implementation | Production requirement |
|---|---|---|
| TEE runtime | Node.js + Express (`tee/abyssal-prover/`) | AWS Nitro Enclave with `nsm_api`, Rust + axum |
| Enclave identity | Vault stores `vector<vector<u8>>` of Ed25519 pubkeys | Vault stores `vector<ID>` referencing Nautilus `Enclave<T>` objects |
| Attestation on register | Vault owner asserts the pubkey | `register_enclave` verifies `NitroAttestationDocument` with PCR0/1/2 (48-byte SHA-384) |
| Seal key fetch in TEE | Direct `SealClient.decrypt()` (TEE has network) | 2-phase load via host: enclave builds PTB + ElGamal pubkey → host fetches from Seal CLI → enclave decrypts response |
| TEE keypair | Deterministic seed (reproducible for testing) | Random keypair generated inside the enclave on every boot |
| Seal key server verification | `verifyKeyServers: false` | `verifyKeyServers: true`, mainnet DKS when available |
| `nullifier_policy == 1` (once-per-epoch) | Currently equivalent to `policy 0` (one-time) | Add per-epoch reset logic to nullifier table |
| Audit Layer 3-5 | Layers 3-4 marked SKIP, Layer 5 PARTIAL | Implement Nautilus attestation verification + multi-party Trusted Setup |
| Trusted Setup | Powers of Tau + deployer beacon contribution | Multi-party MPC ceremony with verifiable contributions |

Every simplification is annotated in the code and tracked in [`CLAUDE.md`](CLAUDE.md).

---

## Roadmap

- **Phase 3 (current):** End-to-end testnet demo with full Seal + Walrus integration.
- **Phase 4 — Real Nautilus integration:** Rust enclave server, on-chain attestation verification, `Enclave<T>` object model. See [`memory/nautilus_integration_guide.md`](.claude/projects/-home-james-projects-abyssal/memory/nautilus_integration_guide.md) for the detailed migration plan.
- **Phase 5 — Production-grade Trusted Setup:** Multi-party ceremony tooling and on-chain ceremony verification.
- **Phase 6 — Mainnet:** Coincides with Seal DKS mainnet launch; migrate Walrus to mainnet storage.

---

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — Formal specification v2.1.1 (20 sections, ~1,800 lines)
- [`CLAUDE.md`](CLAUDE.md) — Engineering rules, gotchas, and critical invariants for contributors
- [`demo/index.html`](demo/index.html) — Static presentation page (bilingual, includes architecture diagrams and on-chain transaction trail)

External references:

- [Sui Groth16 API](https://docs.sui.io/guides/developer/cryptography/groth16)
- [Nautilus Design](https://docs.sui.io/guides/developer/nautilus/nautilus-design)
- [Nautilus + Seal Integration](https://docs.sui.io/guides/developer/nautilus/seal)
- [Seal Documentation](https://seal-docs.wal.app/UsingSeal)
- [Walrus Documentation](https://docs.wal.app/)

---

## Acknowledgments

Abyssal builds on engineering foundations from [SuiCryptoLib](https://github.com/ARZER-TW) (ARZER-TW), which contributed:

- `circuits/poc/format_for_sui.mjs` — snarkjs-to-Sui Arkworks format conversion (G1/G2 compression, LE byte order, y-sign bit handling)
- `circuits/pot13.ptau`, `circuits/pot15.ptau` — Powers of Tau ceremony files
- Reference patterns for Groth16 verification on Move

This work is the first production-direction PFE protocol on Sui. The cryptographic asymmetry it exploits — that `pvk` is verification-complete but logic-blind — is well-known in the literature; the engineering contribution is wiring this insight through Seal, Walrus, and Nautilus into a single end-to-end protocol.

---

## License

This project will be released under an OSI-approved license. License file pending; until then, all rights reserved by the author.

## Author

**ARZER-TW** — [GitHub](https://github.com/ARZER-TW)

For questions or collaboration: open an issue at <https://github.com/ARZER-TW/abyssal/issues>.
