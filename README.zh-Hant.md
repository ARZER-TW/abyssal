# Abyssal

[English](README.md) | [繁體中文](README.zh-Hant.md)

**Sui 上第一個 Private Function Evaluation (PFE) 協議。**

用 Seal IBE 加密 proving key 與 witness calculator,在 AWS Nitro Enclave 內生成 Groth16 證明,只把 verification key 放上鏈。任何人都能驗證證明有效,沒人能反推電路在算什麼。

- **狀態:** 已部署 Sui testnet,端到端驗證通過
- **規範:** [`docs/SPEC.md`](docs/SPEC.md) v2.1.1
- **演示頁:** [`demo/index.html`](demo/index.html)
- **網路:** Sui Testnet
- **Move edition:** 2024.beta

---

## 問題

密碼學長久以來把兩種隱私目標混為一談:

| | 隱藏 | 公開 | 已有解法 |
|---|---|---|---|
| **資料隱私 (Data Privacy)** | 輸入資料 | 計算邏輯 | Aztec、Aleo、ZK-Rollups、Tornado Cash |
| **函數隱私 (PFE)** | 輸入資料**加上計算邏輯本身** | 結果可驗證性 | **任何 production 區塊鏈都未解決** |

銀行的信用評分模型、交易所的風控引擎、保險公司的精算公式——這些是幾十年累積、價值數億美元的商業機密。機構不能放上公鏈(邏輯立即外洩)、也不能維持中心化服務(使用者必須盲目信任)。今天市場用「可信中介」每年繞道處理這個矛盾:評等機構、會計師、顧問公司——這是個年產值千億美元級的市場。

**Abyssal 讓「演算法隱私、結果可信、驗證獨立」同時成立。**

---

## 密碼學洞察

Groth16 trusted setup 產出兩把性質根本不對稱的金鑰:

```
Proving Key (pk) ─── 5-50 MB
  完整編碼了電路的多項式結構。
  生成證明必需。
  可被分析:能看出電路在算什麼。

Verifying Key (vk → pvk) ─── ~600 bytes
  足以驗證來自對應 pk 的任何證明。
  數學上不可能反推電路邏輯。
```

**鏈上驗證一筆證明只需要 pvk,完全不需要 pk。** 而 `.wasm` witness calculator 是電路邏輯的機器碼——可被逆向工程。

Abyssal 的核心構造:

> 用 Seal IBE 把 pk **跟** wasm 都加密;只允許通過 PCR attestation 的 Nautilus enclave 解密。pvk 公開放上鏈。全世界能驗證,沒人能複製。

這在 ZK 應用史上沒有先例。

---

## 運作原理

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Deployer ─────► Seal IBE encrypt(pk, wasm, source)            │
│                                  │                              │
│                                  ▼                              │
│                            Walrus blob 儲存                     │
│                                  │                              │
│                                  ▼                              │
│                     ┌─────────────────────────┐                 │
│                     │  Sui Move VaultConfig   │ ◄── pvk 上鏈    │
│                     │  (shared object)        │                 │
│                     └────────────┬────────────┘                 │
│                                  │                              │
│                                  │ register_enclave             │
│                                  ▼                              │
│   使用者 ─────► Nautilus TEE (AWS Nitro Enclave)                │
│                  1. Seal 解密 pk + wasm                         │
│                  2. snarkjs 產生 Groth16 證明                   │
│                  3. Ed25519 簽 (proof || public_inputs)         │
│                                  │                              │
│                                  ▼                              │
│   submit_proof ──► Move 9 步驗證 ──► VaultProof 物件            │
│                                  │                              │
│                                  ▼                              │
│   第三方協議消費 VaultProof,取得結果。                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**三個角色,沒有可信中介**:

| 角色 | 信任假設 | 他們做不到的事 |
|---|---|---|
| **Deployer**(金融機構/銀行) | 持有 Trusted Setup 的 toxic waste | 不能對不同使用者套用不同規則——pvk 鏈上固定 |
| **TEE 營運方**(AWS Nitro Enclave) | 硬體安全邊界 | 不能洩漏 pk/wasm(attestation 把關 Seal 解密);不能在無有效 witness 下偽造證明 |
| **使用者 / 驗證者** | 驗證時零信任,持有自己的私有輸入 | 任何人架一個 Sui 節點就能驗證證明 |

**安全降級性質**:

- **TEE 硬體被攻破:** 邏輯外洩(商業損失),但**資產安全不受影響**——攻擊者拿到 pk 還是需要滿足所有 constraint 的有效 witness 才能產證明,無法為不符條件的使用者偽造。這是 Abyssal 對純 TEE 隱私鏈(Secret Network、Phala)的根本優勢。
- **Seal key server 串通超過 threshold:** 結論同上——邏輯外洩,資產安全成立。

---

## Testnet 上的真實部署

所有 artifact 都是真實鏈上、任何人可驗證:

| 物件 | ID | 瀏覽器 |
|---|---|---|
| `abyssal` package | `0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777` | [SuiScan](https://suiscan.xyz/testnet/object/0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777) |
| `abyssal-seal-policy` package | `0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8` | [SuiScan](https://suiscan.xyz/testnet/object/0x7e0f816163e4f1bf716db003dca162fd75f11030367a913508ebbf804854fbc8) |
| `abyssal-audit-policy` package | `0xc854ea999c3c3008e0dd978caadb6af4e5c0b8c33dc8197bce2709ed95ea00cf` | [SuiScan](https://suiscan.xyz/testnet/object/0xc854ea999c3c3008e0dd978caadb6af4e5c0b8c33dc8197bce2709ed95ea00cf) |
| 範例 `VaultConfig`(信用評分) | `0x921c99ac92b08906b2034c584fdc692cbd132ef8de1c9e87eb03194afc34f084` | [SuiScan](https://suiscan.xyz/testnet/object/0x921c99ac92b08906b2034c584fdc692cbd132ef8de1c9e87eb03194afc34f084) |
| 該 vault 的 `AuditAllowlist` | `0x2280b8406afd5e094463090e6165701aa574bd893a1c16d58b9178cd6e2c69bc` | [SuiScan](https://suiscan.xyz/testnet/object/0x2280b8406afd5e094463090e6165701aa574bd893a1c16d58b9178cd6e2c69bc) |

範例 vault 裝載了已加密的信用評分電路。其 proving key、witness calculator、電路原始碼都存在 Walrus testnet:

| Blob | Walrus ID |
|---|---|
| 加密的 `pk`(VaultKeyPolicy seal) | `c-k7JX2VUPdkj8qMXOeiFRBaYV_wXcIPJUoURRG6EzU` |
| 加密的 `wasm`(VaultKeyPolicy seal) | `zrGm8z8qHVm7_6Ji9O0TlzWDr96xb3yRv2Atn-94MxI` |
| 加密的電路原始碼(AuditAllowlistPolicy seal) | `NECiydYRxlPQ9PmLP_SUXYQbOWaJH2xd1dUjkr5OL-I` |

`wasm_double_hash`(鏈上電路身份): `2c64b5bb4dbe2e964f24304a1099028025410f8bbc9c1da4aa7f361434cb2279`

---

## 5 分鐘 Demo

最完整的 demo 路徑是 CLI 部署腳本——它會把 Seal + Walrus + Nautilus 三個協議端到端跑一遍,產生真實的鏈上 `VaultProof`。

### 環境準備

- Sui CLI(testnet build)、Walrus CLI(`walrus`)
- Node.js 20+ 搭配 `pnpm` 或 `npm`
- Sui testnet 錢包,餘額 ≥ 1 SUI([faucet](https://docs.sui.io/guides/developer/getting-started/get-coins))
- Walrus 儲存用的 WAL tokens

### 跑完整流程

```bash
# 1. 安裝依賴
pnpm install
cd sdk && pnpm install && cd ..
cd tee/abyssal-prover && pnpm install && cd ../..
cd frontend && pnpm install && cd ..

# 2. 編譯 demo 電路(Powers of Tau ceremony 檔已快取在 circuits/)
cd circuits/credit_score
node setup.mjs        # 跑 snarkjs groth16 setup
cd ../..

# 3. 啟動 TEE prover(hackathon mock,非真實 Nitro Enclave)
cd tee/abyssal-prover
pnpm start            # 監聽 :3001
# (另開一個 terminal 讓它跑)

# 4. 部署:Seal 加密 → Walrus 上傳 → 鏈上建 vault → audit allowlist → TEE 載入電路 → 端到端產證明
node scripts/deploy_full.mjs
```

預期輸出:新的 `VaultConfig` shared object、`AuditAllowlist`、三個 Walrus blob ID、一次 enclave 註冊,以及一個由真實 Groth16 證明送出產生的 `VaultProof` 物件。腳本會把所有 ID 寫入 `scripts/deployment.json`。

### 驗證一個既有的證明

```bash
sui client call \
  --package 0x56b8bc8dc17d06631172831794b3111dbda84c10e99d2f92d69877fe02c9b777 \
  --module abyssal_registry \
  --function verify_vault_proof \
  --args <vault_id> <proof_id>
```

### 獨立審計(五層審計鏈的 Layer 1+2)

```bash
node scripts/audit_vault.mjs
```

從 Walrus 解密電路原始碼(需要在 AuditAllowlist 上)、重新編譯、比對 `wasm_double_hash` 跟鏈上是否一致。

---

## 目錄結構

```
abyssal/
├── move/
│   ├── abyssal/                    核心:VaultConfig + VaultProof + 生命週期
│   ├── abyssal-seal-policy/        TEE 用的 Seal access control
│   └── abyssal-audit-policy/       審計者用的 Seal access control
├── circuits/credit_score/          VECS 合規 demo 電路(819 constraints)
├── tee/abyssal-prover/             Node.js TEE server(hackathon Nitro mock)
├── sdk/                            TypeScript SDK(早期階段)
├── frontend/                       React + dApp Kit UI(browse/verify 可用)
├── scripts/
│   ├── deploy_full.mjs             完整流程:加密 → 上傳 → 部署 → 註冊 → 產證明
│   └── audit_vault.mjs             審計者流程(Layer 1+2)
├── demo/                           靜態演示頁
├── docs/SPEC.md                    正式規範 v2.1.1
└── CLAUDE.md                       專案規則與 gotchas
```

---

## 技術規範

### VECS — Verifier-Equivalent Circuit Standard(驗證對等電路標準)

所有 Abyssal 電路必須**依此順序輸出剛好 4 個 public input**(在 Groth16 的 8 input 上限內),合計 **128 bytes**:

```
[0..32)    nullifier         = Poseidon(user_secret, vault_id_field, epoch)
[32..64)   result_commitment = Poseidon(result_value, result_salt)
[64..96)   vault_id_hash     = Poseidon(vault_id_field)
[96..128)  expiry_epoch      u64 LE,zero-pad 至 32 bytes(BN254 field 元素)
```

所有值都是 BN254 scalar field 元素、little-endian 編碼。協議強制 **semantic opacity**:任何 public input 都不能洩漏業務語意。詳見 [SPEC §5](docs/SPEC.md)。

### `submit_proof` 9 步鏈上驗證

1. Vault 未暫停
2. Enclave 公鑰已註冊於該 vault
3. Ed25519 驗 TEE 對 `proof_bytes || public_inputs_bytes` 的簽名
4. `public_inputs_bytes.length() == 128`
5. 依固定 byte offset 解析 4 個 input
6. `vault_id_hash == Poseidon(vault_id_u256 mod BN254_R)`
7. `current_epoch ≤ expiry_epoch ≤ current_epoch + proof_validity_epochs`
8. 依 `nullifier_policy` 檢查 nullifier
9. `groth16::verify_groth16_proof` 用鏈上 `pvk` 驗證

詳見 [SPEC §6.4](docs/SPEC.md)。

### 密碼學原語

| 用途 | 原語 | 函式庫 |
|---|---|---|
| 證明系統 | Groth16 over BN254 | `sui::groth16`(鏈上)、`snarkjs`(TEE) |
| 電路內雜湊 | Poseidon-BN254 | `circomlib`(電路)、`sui::poseidon`(鏈上) |
| TEE 簽名 | Ed25519 | `sui::ed25519`、`tweetnacl` |
| 電路綁定雜湊 | SHA-256 of SHA-256(`wasm_double_hash`) | `crypto` 標準函式庫 |
| IBE 加密 | Seal threshold IBE | `@mysten/seal` |
| Blob 儲存 | Walrus erasure-coded | `@mysten/walrus`、Walrus CLI |
| TEE attestation(production) | AWS Nitro NSM | `sui::nitro_attestation` |

---

## 信任模型

### Abyssal 消除的信任

- 不需要信任機構「沒偷改規則」——`pvk` 鏈上固定,每筆證明都對同一個電路,數學保證。
- 不需要信任「同一套標準套用到所有人」——電路內沒有依使用者身份分支的動態邏輯,同一個 `pvk` 驗證所有證明。
- 不需要信任「使用者資料沒外洩」——私有輸入永不離開 TEE 硬體邊界。
- 不需要信任「審計報告真實」——指定審計人獨立解密電路原始碼、重新編譯、驗證 `wasm_double_hash` 一致。

### 殘留信任(所有外部文件必須誠實揭露)

| 假設 | 描述 | 緩解 |
|---|---|---|
| AWS Nitro Enclave 硬體 | NSM 無後門 | 業界標準 TEE 假設;所有 confidential compute 同樣 |
| Seal key server 誠實 | Hackathon:2-of-2 testnet servers。Production:t-of-n DKS | Mainnet 提高 threshold 與節點數 |
| TEE 原始碼與 PCR 一致 | Reproducible build;審計者從解密的原始碼重新編譯 | 由 Layer 1+2 審計腳本提供 |
| Trusted Setup ceremony 完整性 | Demo 用 Powers of Tau + deployer 貢獻 | Production 應用多方 ceremony |

---

## Hackathon 簡化清單

我們明確標示哪些是 hackathon 等級、哪些需要 production 化:

| 元件 | Hackathon 實作 | Production 要求 |
|---|---|---|
| TEE runtime | Node.js + Express(`tee/abyssal-prover/`) | AWS Nitro Enclave 配 `nsm_api`、Rust + axum |
| Enclave 身份 | Vault 存 `vector<vector<u8>>` 的 Ed25519 公鑰 | Vault 存 `vector<ID>` 指向 Nautilus `Enclave<T>` 物件 |
| 註冊時 attestation | Vault owner 直接確認公鑰 | `register_enclave` 驗 `NitroAttestationDocument`,含 PCR0/1/2(48-byte SHA-384) |
| TEE 內 Seal key 取得 | 直接 `SealClient.decrypt()`(TEE 有網路) | 經 host 中介的 2-phase load:enclave 構造 PTB + ElGamal 公鑰 → host 從 Seal CLI 取 → enclave 解密回應 |
| TEE keypair | Deterministic seed(便於測試重現) | Enclave 每次開機在 enclave 內生成隨機 keypair |
| Seal key server 驗證 | `verifyKeyServers: false` | `verifyKeyServers: true`,mainnet DKS 上線後啟用 |
| `nullifier_policy == 1`(once-per-epoch) | 目前等同 `policy 0`(one-time) | 加上 nullifier table 的 per-epoch reset 邏輯 |
| Audit Layer 3-5 | Layer 3-4 標 SKIP、Layer 5 標 PARTIAL | 實作 Nautilus attestation 驗證 + 多方 Trusted Setup |
| Trusted Setup | Powers of Tau + deployer beacon | 多方 MPC ceremony,貢獻可驗證 |

每個簡化都在程式碼內標註,並追蹤於 [`CLAUDE.md`](CLAUDE.md)。

---

## Roadmap

- **Phase 3(當前):** Testnet 端到端 demo,Seal + Walrus 完整整合。
- **Phase 4 — 真實 Nautilus 整合:** Rust enclave server、鏈上 attestation 驗證、`Enclave<T>` 物件模型。詳細遷移計劃見 issue tracker。
- **Phase 5 — Production 級 Trusted Setup:** 多方 ceremony 工具與鏈上 ceremony 驗證。
- **Phase 6 — Mainnet:** 配合 Seal DKS mainnet 上線;Walrus 遷移至 mainnet 儲存。

---

## 文件

- [`docs/SPEC.md`](docs/SPEC.md) — 正式規範 v2.1.1(20 節、約 1,800 行)
- [`CLAUDE.md`](CLAUDE.md) — 工程規則、gotchas、貢獻者必讀的關鍵不變量
- [`demo/index.html`](demo/index.html) — 靜態演示頁(雙語,含架構圖與鏈上交易軌跡)

外部參考:

- [Sui Groth16 API](https://docs.sui.io/guides/developer/cryptography/groth16)
- [Nautilus Design](https://docs.sui.io/guides/developer/nautilus/nautilus-design)
- [Nautilus + Seal Integration](https://docs.sui.io/guides/developer/nautilus/seal)
- [Seal 文件](https://seal-docs.wal.app/UsingSeal)
- [Walrus 文件](https://docs.wal.app/)

---

## 致謝

Abyssal 建立在 [SuiCryptoLib](https://github.com/ARZER-TW)(ARZER-TW)的工程基礎上,沿用以下成果:

- `circuits/poc/format_for_sui.mjs` — snarkjs 至 Sui Arkworks 格式轉換(G1/G2 壓縮、LE byte order、y-sign bit 處理)
- `circuits/pot13.ptau`、`circuits/pot15.ptau` — Powers of Tau ceremony 檔
- Move 上 Groth16 驗證的 reference pattern

這份作品是 Sui 上第一個朝 production 方向設計的 PFE 協議。它利用的密碼學不對稱性——`pvk` 驗證完備但對邏輯失明——在學術文獻中早有討論;本專案的工程貢獻在於把這個洞察透過 Seal、Walrus、Nautilus 接成單一端到端協議。

---

## License

本專案將以 OSI 認可的開源 license 釋出。License 檔尚未確定;在此之前,所有權利保留於作者。

## 作者

**ARZER-TW** — [GitHub](https://github.com/ARZER-TW)

有問題或合作意願,請至 <https://github.com/ARZER-TW/abyssal/issues> 開 issue。
