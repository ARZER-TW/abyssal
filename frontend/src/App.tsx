import { useState } from "react";
import {
  ConnectButton,
  SuiClientProvider,
  WalletProvider,
  createNetworkConfig,
} from "@mysten/dapp-kit";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@mysten/dapp-kit/dist/index.css";

import DeployVault from "./pages/DeployVault.tsx";
import GenerateProof from "./pages/GenerateProof.tsx";
import VerifyConsume from "./pages/VerifyConsume.tsx";
import BrowseVaults from "./pages/BrowseVaults.tsx";
import { colors } from "./styles.ts";

const queryClient = new QueryClient();
const { networkConfig } = createNetworkConfig({
  testnet: { url: "https://fullnode.testnet.sui.io:443", network: "testnet" },
});

type Tab = "deploy" | "prove" | "verify" | "browse";

const tabs: { key: Tab; label: string }[] = [
  { key: "deploy", label: "Deploy Vault" },
  { key: "prove", label: "Generate Proof" },
  { key: "verify", label: "Verify / Consume" },
  { key: "browse", label: "Browse Vaults" },
];

function AppInner() {
  const [activeTab, setActiveTab] = useState<Tab>("deploy");

  return (
    <div
      style={{
        minHeight: "100vh",
        background: colors.bg,
        color: colors.text,
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      }}
    >
      {/* Header */}
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "16px 24px",
          borderBottom: `1px solid ${colors.cardBorder}`,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <h1
            style={{
              fontSize: "20px",
              fontWeight: 700,
              margin: 0,
              color: colors.primary,
              letterSpacing: "0.5px",
            }}
          >
            ABYSSAL
          </h1>
          <span
            style={{
              fontSize: "12px",
              color: colors.textMuted,
              padding: "2px 8px",
              background: colors.card,
              borderRadius: "4px",
            }}
          >
            Private Function Evaluation
          </span>
        </div>
        <ConnectButton />
      </header>

      {/* Tab Navigation */}
      <nav
        style={{
          display: "flex",
          gap: "0",
          padding: "0 24px",
          borderBottom: `1px solid ${colors.cardBorder}`,
        }}
      >
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              padding: "14px 20px",
              background: "transparent",
              border: "none",
              borderBottom:
                activeTab === tab.key
                  ? `2px solid ${colors.primary}`
                  : "2px solid transparent",
              color:
                activeTab === tab.key ? colors.text : colors.textMuted,
              fontSize: "14px",
              fontWeight: activeTab === tab.key ? 600 : 400,
              cursor: "pointer",
              transition: "all 0.15s",
            }}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main>
        {activeTab === "deploy" && <DeployVault />}
        {activeTab === "prove" && <GenerateProof />}
        {activeTab === "verify" && <VerifyConsume />}
        {activeTab === "browse" && <BrowseVaults />}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SuiClientProvider networks={networkConfig} defaultNetwork="testnet">
        <WalletProvider autoConnect>
          <AppInner />
        </WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  );
}
