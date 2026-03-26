# Abyssal — Project Instructions

## 核心原则

1. **SPEC 是唯一真理来源。** 所有实作决策以 `docs/SPEC.md` (v2.1.1) 为准。当代码与 SPEC 冲突时，以 SPEC 为准。
2. **Sui Stack 以官方文档为准。** Sui Move、Seal、Walrus、Nautilus 的所有相关内容永远以 https://docs.sui.io/ 上的文档为准。不依赖过时的博客文章或第三方资料。
3. **先思考，再行动。** 做任何修改前先深度思考影响范围和潜在风险。品质永远优先于速度。
4. **不猜测，要验证。** 对 Sui API、Seal SDK、Walrus、Nautilus 的行为不做假设，用代码实测确认。

## 项目概述

Abyssal 是第一个 Web3 Private Function Evaluation (PFE) 协议。通过加密 Groth16 proving key + wasm（Seal IBE + Walrus），由 Nautilus TEE 在硬件安全边界内生成 proof，pvk 上链让任何人验证。

**前身：** SuiCryptoLib (`/home/james/projects/suicryptolib/`)

## 关键技术约束（必须遵守）

- `pvk_from_bytes` 重建 pvk（低 gas），不用 `prepare_verifying_key`（高 gas）
- `ctx.epoch()` 获取 Sui epoch（~24h），`clock::epoch()` 不存在
- `poseidon::poseidon_bn254(&vector[...])` — 参数是 `&vector<u256>`，返回 `u256`
- PCR 是 48 bytes SHA-384，不是 32 bytes
- Seal `seal_approve` 函数名必须以 `seal_approve` 开头，第一个参数必须是 `id: vector<u8>`
- Seal 通过 `dry_run_transaction_block` 评估 `seal_approve`，只读不改状态
- Nautilus enclave 无直接网络访问，Seal key load 需要 host 做中介（2-phase）
- Groth16 最多 8 个 public inputs（VECS 标准用 4 个）
- Event struct 必须在 emit 所在的同一个 module 中定义
- Sui `Table` 不可迭代，需要配合 `vector` 做遍历

## Hackathon 简化

- Nautilus TEE 用 mock（普通服务器模拟）
- Seal 用 testnet DKS 或单 key server
- Move 合约中 enclave 用 pubkey 注册（不引用 Nautilus Enclave 对象）

## 文件结构

```
/home/james/projects/abyssal/
├── docs/SPEC.md                  ← 唯一规格来源
├── move/                         ← Move 合约
│   ├── sources/
│   │   ├── abyssal_types.move    ← 字节转换 helpers
│   │   ├── abyssal_registry.move ← VaultConfig + VaultProof + 核心逻辑
│   │   └── abyssal_registry_tests.move
│   └── Move.toml
├── circuits/                     ← VECS 标准电路（待建）
├── sdk/                          ← TypeScript SDK（待建）
├── tee/                          ← Nautilus TEE mock（待建）
└── frontend/                     ← Demo 前端（待建）
```

## 当前进度

- Phase 1 进行中：abyssal_types (7 tests) + abyssal_registry (7 tests) = 14 tests passing
- 剩余 submit_proof/verify/consume 测试需要 Phase 2 电路测试向量

## 过往踩坑记录

- `use sui::clock::Clock` 只导入类型不导入函数 → 用 `use sui::clock::{Self, Clock}`
- circomlibjs 在浏览器需要 `vite-plugin-node-polyfills`（Buffer/events/util）
- snarkjs 在 Vite 需要 `optimizeDeps.include: ["snarkjs"]`
- Balance<SUI> 的 JSON 序列化是直接字符串不是 `{ fields: { value } }`
- 格式转换（snarkjs → Sui Arkworks）的参考实现在 suicryptolib 的 `circuits/poc/format_for_sui.mjs`

## 编码规范

- Move edition: 2024.beta
- 所有 Move 测试用 `sui::test_scenario`
- 前端语言：简体中文
- 不在代码中使用 emoji
- Commit message 不标注 AI co-author
