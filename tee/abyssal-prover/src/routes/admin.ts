import { Router, type Request, type Response } from "express";
import { loadCircuit } from "../circuit.js";

const router = Router();

// Load circuit zkey + wasm from local filesystem paths.
router.post("/load_circuit", (req: Request, res: Response) => {
  const { zkeyPath, wasmPath, expectedWasmDoubleHash } = req.body as {
    zkeyPath?: string;
    wasmPath?: string;
    expectedWasmDoubleHash?: string;
  };

  if (!zkeyPath || !wasmPath) {
    res.status(400).json({ error: "zkeyPath and wasmPath are required" });
    return;
  }

  try {
    loadCircuit(zkeyPath, wasmPath, expectedWasmDoubleHash);
    res.json({ status: "ok" });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: message });
  }
});

// Hackathon mock: Seal key load phase 1.
// In production Nautilus, this initiates a 2-phase key load via the host.
router.post("/init_seal_key_load", (_req: Request, res: Response) => {
  res.json({
    status: "mock",
    message: "Seal key load not required in hackathon mode",
  });
});

// Hackathon mock: Seal key load phase 2.
router.post("/complete_seal_key_load", (_req: Request, res: Response) => {
  res.json({
    status: "mock",
    message: "Seal key load not required in hackathon mode",
  });
});

export default router;
