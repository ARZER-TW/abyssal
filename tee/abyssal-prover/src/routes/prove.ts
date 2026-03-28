import { Router, type Request, type Response } from "express";
// @ts-expect-error -- snarkjs has no type declarations
import * as snarkjs from "snarkjs";
import { isCircuitLoaded, getZkeyPath, getWasmPath } from "../circuit.js";
import { getPublicKey, sign } from "../keys.js";

const router = Router();

// ---------------------------------------------------------------------------
// BN254 format conversion: snarkjs JSON -> Sui Arkworks compressed bytes
// ---------------------------------------------------------------------------

const BN254_P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// Convert a decimal string field element to 32-byte little-endian buffer.
function fieldToLE(decStr: string): Buffer {
  const n = BigInt(decStr);
  const buf = Buffer.alloc(32);
  let v = n;
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

// Determine the y-sign bit for a compressed point.
// If y > (p-1)/2 the sign bit is set (bit 7 of the last byte).
function ySignBit(yDec: string): number {
  const y = BigInt(yDec);
  return y > (BN254_P - 1n) / 2n ? 0x80 : 0x00;
}

// Compress a G1 point (from snarkjs array-of-3 projective -> affine strings).
// snarkjs proof fields are already affine [x, y, "1"].
function compressG1(point: string[]): Buffer {
  const xLE = fieldToLE(point[0]);
  // Set y-sign in bit 7 of the last byte of x.
  xLE[31] |= ySignBit(point[1]);
  return xLE; // 32 bytes
}

// Compress a G2 point. G2 x-coordinate has two components (c0, c1).
// snarkjs G2: [[x.c0, x.c1], [y.c0, y.c1], ["1","0"]]
// Fp2 lexicographic ordering: compare c1 first, if zero compare c0.
function compressG2(point: string[][]): Buffer {
  const xc0LE = fieldToLE(point[0][0]);
  const xc1LE = fieldToLE(point[0][1]);
  const yC0 = BigInt(point[1][0]);
  const yC1 = BigInt(point[1][1]);
  const halfP = (BN254_P - 1n) / 2n;
  const yNeg = yC1 !== 0n ? yC1 > halfP : yC0 > halfP;
  if (yNeg) {
    xc1LE[31] |= 0x80;
  }
  return Buffer.concat([xc0LE, xc1LE]); // 64 bytes
}

// Encode proof to 128 bytes: A(G1,32) || B(G2,64) || C(G1,32).
function encodeProof(proof: {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}): Buffer {
  const a = compressG1(proof.pi_a);
  const b = compressG2(proof.pi_b);
  const c = compressG1(proof.pi_c);
  return Buffer.concat([a, b, c]); // 128 bytes
}

// Encode public inputs: each signal as 32-byte LE scalar.
function encodePublicInputs(signals: string[]): Buffer {
  const buffers = signals.map((s) => fieldToLE(s));
  return Buffer.concat(buffers);
}

// ---------------------------------------------------------------------------
// POST /prove
// ---------------------------------------------------------------------------

router.post("/", async (req: Request, res: Response) => {
  if (!isCircuitLoaded()) {
    res.status(400).json({ error: "Circuit not loaded. Call /admin/load_circuit first." });
    return;
  }

  const { privateInputs } = req.body as {
    privateInputs?: Record<string, string>;
  };

  if (!privateInputs || typeof privateInputs !== "object") {
    res.status(400).json({ error: "privateInputs (object) is required" });
    return;
  }

  try {
    // Generate witness and Groth16 proof.
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      privateInputs,
      getWasmPath(),
      getZkeyPath(),
    );

    // Encode to Sui Arkworks compressed format.
    const proofBytes = encodeProof(proof);
    const publicInputsBytes = encodePublicInputs(publicSignals as string[]);

    // Sign the concatenation: proof_bytes || public_inputs_bytes.
    const payload = Buffer.concat([proofBytes, publicInputsBytes]);
    const signature = sign(new Uint8Array(payload));

    res.json({
      proof_hex: proofBytes.toString("hex"),
      public_inputs_hex: publicInputsBytes.toString("hex"),
      signature_hex: Buffer.from(signature).toString("hex"),
      pubkey_hex: Buffer.from(getPublicKey()).toString("hex"),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: message });
  }
});

export default router;
