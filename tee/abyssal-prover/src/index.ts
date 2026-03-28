import express from "express";
import proveRouter from "./routes/prove.js";
import adminRouter from "./routes/admin.js";
import sealLoadRouter from "./routes/seal-load.js";
import { isCircuitLoaded } from "./circuit.js";
import { getPublicKey, getWalletAddress } from "./keys.js";

const app = express();
const PORT = Number(process.env.PORT) || 3001;

app.use(express.json());

// Routes
app.use("/prove", proveRouter);
app.use("/admin", adminRouter);
app.use("/admin", sealLoadRouter);

app.get("/health", (_req, res) => {
  const pubkeyHex = Buffer.from(getPublicKey()).toString("hex");
  res.json({
    status: "ok",
    circuitLoaded: isCircuitLoaded(),
    pubkey: pubkeyHex,
    walletAddress: getWalletAddress(),
  });
});

app.listen(PORT, () => {
  console.log(`[abyssal-prover] listening on port ${PORT}`);
});
