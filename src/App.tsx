import React, { useState, useEffect } from "react";
import { Navbar, TabType } from "./components/Navbar";
import { LiveScanner } from "./components/LiveScanner";
import { VisualSimilarityInspector } from "./components/VisualSimilarityInspector";
import { ApkAnalyzer } from "./components/ApkAnalyzer";
import { CTLogStreamer } from "./components/CTLogStreamer";
import { ThreatFeed } from "./components/ThreatFeed";
import { CampaignGraph } from "./components/CampaignGraph";
import { TakedownGenerator } from "./components/TakedownGenerator";
import { BenchmarkEvaluation } from "./components/BenchmarkEvaluation";
import { ThreatDetailModal } from "./components/ThreatDetailModal";

import {
  INITIAL_THREATS,
  INITIAL_CAMPAIGNS,
  MOCK_GRAPH_DATA,
} from "./data/mockThreats";
import { ThreatItem, ThreatStatus } from "./types/threat";
import { apiClient } from "./services/api";

export function App() {
  const [activeTab, setActiveTab] = useState<TabType>("detector");
  const [threats, setThreats] = useState<ThreatItem[]>(INITIAL_THREATS);
  const [campaigns, setCampaigns] = useState(INITIAL_CAMPAIGNS);
  const [graphData, setGraphData] = useState(MOCK_GRAPH_DATA);
  const [selectedThreatId, setSelectedThreatId] = useState<string>(
    threats[0]?.id || "thr-8901",
  );
  const [detailModalThreat, setDetailModalThreat] = useState<ThreatItem | null>(
    null,
  );

  // Load live data from backend
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [threatsList, campaignsList, graph] = await Promise.all([
        apiClient.getThreats(),
        apiClient.getCampaigns(),
        apiClient.getGraph(),
      ]);

      if (threatsList && threatsList.length > 0) {
        setThreats(threatsList);
      }
      if (campaignsList && campaignsList.length > 0) {
        setCampaigns(campaignsList);
      }
      if (graph && graph.nodes && graph.nodes.length > 0) {
        setGraphData(graph);
      }
    } catch (err) {
      console.warn("Initial data load warning:", err);
    }
  };

  const activeThreatCount = threats.filter(
    (t) => t.status !== "TAKEN_DOWN" && t.status !== "FALSE_POSITIVE",
  ).length;

  const handleSelectThreat = (threatId: string) => {
    const found = threats.find((t) => t.id === threatId);
    if (found) {
      setSelectedThreatId(threatId);
      setDetailModalThreat(found);
    }
  };

  const handleOpenSimilarity = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab("similarity");
  };

  const handleOpenTakedowns = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab("takedowns");
  };

  const handleUpdateStatus = async (
    threatId: string,
    newStatus: ThreatStatus,
  ) => {
    setThreats((prev) =>
      prev.map((t) => (t.id === threatId ? { ...t, status: newStatus } : t)),
    );
    await apiClient.updateThreatStatus(threatId, newStatus);
  };

  const handleAddScannedThreat = async (result: any) => {
    if (!result.isFake) return;

    const newThreat: ThreatItem = {
      id: `thr-${Date.now().toString().slice(-4)}`,
      url: result.rawInput.startsWith("http")
        ? result.rawInput
        : `https://${result.domain}`,
      domain: result.domain,
      targetBrand: result.matchedBrand || "SBI YONO",
      threatType: result.threatType,
      discoverySource: "USER_REPORT",
      discoveryTimestamp: new Date()
        .toISOString()
        .replace("T", " ")
        .slice(0, 19),
      severity: result.severity,
      status: "CONFIRMED_PHISH",
      similarityScore: result.overallFakePercentage,
      pHashDistance: result.pHashDistance,
      structuralSSIM: result.structuralSSIM,
      domEditDistance: result.domEditDistance,
      logoConfidence: result.logoMatchConfidence,
      ip: result.telemetry?.ipInfo?.ip || "185.220.101.44",
      asn: result.telemetry?.ipInfo?.asn || "AS44050",
      asnName:
        result.telemetry?.ipInfo?.asnName || "Petersburg Offshore Networks",
      country: result.telemetry?.ipInfo?.country || "Seychelles (RU Host)",
      countryCode: result.telemetry?.ipInfo?.countryCode || "SC",
      registrar: result.telemetry?.ipInfo?.registrar || "NameSilo LLC",
      sslIssuer: result.telemetry?.ssl?.issuer || "Let's Encrypt Authority E6",
      sslSerial: result.telemetry?.ssl?.serialNumber || "04a2991823ab",
      dnsNameservers: result.telemetry?.dns?.nsRecords || [
        "ns1.bulletproof.is",
        "ns2.bulletproof.is",
      ],
      extractedUPI_VPA: result.extractedVpa,
      extractedPhoneNumbers: result.extractedPhoneNumbers,
      qrCodePayload: result.qrIntentDetected
        ? `upi://pay?pa=${result.extractedVpa?.[0] || "fraud@paytm"}&pn=Verify&am=1.00`
        : undefined,
      campaignId: "camp-yono-01",
      campaignName: result.attributedCampaign,
      threatActorSyndicate: result.syndicate,
      evasionTactics: result.evasionTactics,
      screenshotUrl: "/assets/evidence/sbi_clone.webp",
      genuineReferenceUrl: `https://${result.genuineBrandDomain}`,
      evidenceHash:
        result.telemetry?.evidenceSha256 ||
        "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
      timeline: [
        {
          time: new Date().toLocaleTimeString(),
          event: `Source analyzed: detected ${result.overallFakePercentage}% Fake probability`,
          actor: "Autonomous Sentinel Engine",
        },
      ],
    };

    setThreats((prev) => [newThreat, ...prev]);
    setSelectedThreatId(newThreat.id);
    await apiClient.addThreat(newThreat);
  };

  const handleInspectDomainFromCT = (domain: string) => {
    setActiveTab("detector");
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        threatCount={activeThreatCount}
      />

      {/* Main Page Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === "detector" && (
          <LiveScanner
            onAddThreat={handleAddScannedThreat}
            onNavigateToTakedowns={() => setActiveTab("takedowns")}
            onNavigateToSimilarity={() => setActiveTab("similarity")}
          />
        )}

        {activeTab === "apk" && <ApkAnalyzer />}

        {activeTab === "similarity" && (
          <VisualSimilarityInspector
            threats={threats}
            selectedThreatId={selectedThreatId}
          />
        )}

        {activeTab === "threats" && (
          <ThreatFeed
            threats={threats}
            campaigns={campaigns}
            onSelectThreat={handleSelectThreat}
            onOpenSimilarity={handleOpenSimilarity}
            onOpenTakedowns={handleOpenTakedowns}
            onUpdateStatus={handleUpdateStatus}
            onRefresh={loadData}
          />
        )}

        {activeTab === "takedowns" && (
          <TakedownGenerator
            threats={threats}
            selectedThreatId={selectedThreatId}
          />
        )}

        {activeTab === "benchmarks" && <BenchmarkEvaluation />}
      </main>

      {/* Forensic Modal */}
      <ThreatDetailModal
        threat={detailModalThreat}
        onClose={() => setDetailModalThreat(null)}
        onOpenSimilarity={handleOpenSimilarity}
        onOpenTakedowns={handleOpenTakedowns}
      />

      {/* Modern Light Footer */}
      <footer className="border-t border-slate-200 py-4 bg-white text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span className="text-slate-700 font-medium">
              PhishNet v2.0 — Autonomous Anti-Phishing & UPI Fraud Defense Pipeline
            </span>
          </div>
          <span className="text-slate-400">
            Automated Crawler • Visual Similarity • Syndicate Graph • 1-Click Takedowns
          </span>
        </div>
      </footer>
    </div>
  );
}

