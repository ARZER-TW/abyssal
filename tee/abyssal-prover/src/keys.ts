import nacl from "tweetnacl";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

// ===== Ephemeral Ed25519 keypair (signs /prove responses) =====
// In production Nautilus TEE: random, regenerated on each enclave restart.
// For dev/test: deterministic seed for reproducibility.
const DEV_SEED = new Uint8Array(32);
DEV_SEED[0] = 42;

const ephemeralKeypair = nacl.sign.keyPair.fromSeed(DEV_SEED);

export function getPublicKey(): Uint8Array {
  return ephemeralKeypair.publicKey;
}

export function sign(message: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, ephemeralKeypair.secretKey);
}

// ===== Seal wallet Ed25519 keypair (transaction sender for seal_approve) =====
// In production Nautilus TEE: separate random keypair, never leaves enclave.
// The wallet address doesn't need SUI (dry-run doesn't consume gas).
const WALLET_SEED = new Uint8Array(32);
WALLET_SEED[0] = 43; // Different seed from ephemeral

const walletKeypair = Ed25519Keypair.fromSecretKey(WALLET_SEED);

export function getWalletKeypair(): Ed25519Keypair {
  return walletKeypair;
}

export function getWalletAddress(): string {
  return walletKeypair.toSuiAddress();
}

export function getWalletPublicKeyBytes(): Uint8Array {
  return walletKeypair.getPublicKey().toRawBytes();
}

// Sign a message with the ephemeral key (for seal_approve sig argument)
export function signWithEphemeral(message: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, ephemeralKeypair.secretKey);
}
