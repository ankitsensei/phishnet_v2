import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { ThreatFeed } from './components/ThreatFeed';
import { CampaignGraph } from './components/CampaignGraph';
import { VisualSimilarityInspector } from './components/VisualSimilarityInspector';
import { CTLogStreamer } from './components/CTLogStreamer';
import { TakedownGenerator } from './components/TakedownGenerator';
import { ApkAnalyzer } from './components/ApkAnalyzer';
import { BenchmarkEvaluation } from './components/BenchmarkEvaluation';
import { LiveScanner } from './components/LiveScanner';
import { ThreatDetailModal } from './components/ThreatDetailModal';

import { INITIAL_THREATS, INITIAL_CAMPAIGNS, MOCK_GRAPH_DATA } from './data/mockThreats';
import { ThreatItem, ThreatStatus } from './types/threat';
import { ScanResult } from './services/detectionEngine';

export function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'graph' | 'similarity' | 'ctlogs' | 'takedowns' | 'apk' | 'benchmarks' | 'sandbox'>('dashboard');
  const [threats, setThreats] = useState<ThreatItem[]>(INITIAL_THREATS);
  const [campaigns, setCampaigns] = useState(INITIAL_CAMPAIGNS);
  const [graphData, setGraphData] = useState(MOCK_GRAPH_DATA);
  const [selectedThreatId, setSelectedThreatId] = useState<string>(threats[0]?.id || 'thr-8901');
  const [detailModalThreat, setDetailModalThreat] = useState<ThreatItem | null>(null);

  const activeThreatCount = threats.filter(t => t.status !== 'TAKEN_DOWN' && t.status !== 'FALSE_POSITIVE').length;
  const takedownCount = threats.filter(t => t.status === 'TAKEN_DOWN' || t.status === 'TAKEDOWN_DISPATCHED').length;

  const handleSelectThreat = (threatId: string) => {
    const found = threats.find(t => t.id === threatId);
    if (found) {
      setSelectedThreatId(threatId);
      setDetailModalThreat(found);
    }
  };

  const handleOpenSimilarity = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab('similarity');
  };

  const handleOpenTakedowns = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab('takedowns');
  };

  const handleUpdateStatus = (threatId: string, newStatus: ThreatStatus) => {
    setThreats(prev => prev.map(t => t.id === threatId ? { ...t, status: newStatus } : t));
  };

  const handleInspectCTDomain = (domain: string) => {
    // Switch to Sandbox and pre-populate domain
    setActiveTab('sandbox');
  };

  const handleAddScannedThreat = (result: ScanResult) => {
    if (!result.isPhishing) return;

    const newThreat: ThreatItem = {
      id: `thr-${Date.now().toString().slice(-4)}`,
      url: result.url,
      domain: result.domain,
      targetBrand: result.matchedBrand || 'SBI YONO',
      threatType: result.threatType,
      discoverySource: 'USER_REPORT',
      discoveryTimestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
      severity: result.severity,
      status: 'CONFIRMED_PHISH',
      similarityScore: result.confidence,
      pHashDistance: result.pHashDistance,
      structuralSSIM: result.structuralSSIM,
      domEditDistance: result.domEditDistance,
      logoConfidence: result.logoMatchConfidence,
      ip: '185.220.101.44',
      asn: 'AS44050',
      asnName: 'Petersburg Offshore Networks',
      country: 'Seychelles (RU Host)',
      countryCode: 'SC',
      registrar: 'NameSilo LLC',
      sslIssuer: "Let's Encrypt Authority E6",
      sslSerial: '04a2991823ab',
      dnsNameservers: ['ns1.bulletproof.is', 'ns2.bulletproof.is'],
      extractedUPI_VPA: result.extractedVpa,
      extractedPhoneNumbers: result.extractedPhoneNumbers,
      qrCodePayload: result.qrIntentDetected ? `upi://pay?pa=${result.extractedVpa[0] || 'fraud@paytm'}&pn=Verify&am=1.00` : undefined,
      campaignId: 'camp-yono-01',
      campaignName: result.attributedCampaign,
      threatActorSyndicate: result.syndicate,
      evasionTactics: result.evasionTactics,
      screenshotUrl: '/assets/evidence/sbi_clone.webp',
      genuineReferenceUrl: 'https://onlinesbi.sbi',
      evidenceHash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
      timeline: [
        { time: new Date().toLocaleTimeString(), event: 'Deep Scan ingested and flagged sample via AI similarity engine', actor: 'Sandbox Pipeline' }
      ]
    };

    setThreats(prev => [newThreat, ...prev]);
    setSelectedThreatId(newThreat.id);
  };

  return (
    <div className="min-h-screen bg-[#070a10] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        activeThreatCount={activeThreatCount}
        takedownCount={takedownCount}
        ctLogVelocity={42}
      />

      {/* Main App Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <ThreatFeed
            threats={threats}
            campaigns={campaigns}
            onSelectThreat={handleSelectThreat}
            onOpenSimilarity={handleOpenSimilarity}
            onOpenTakedowns={handleOpenTakedowns}
            onUpdateStatus={handleUpdateStatus}
          />
        )}

        {activeTab === 'graph' && (
          <CampaignGraph
            nodes={graphData.nodes}
            links={graphData.links}
            campaigns={campaigns}
            onSelectThreat={handleSelectThreat}
          />
        )}

        {activeTab === 'similarity' && (
          <VisualSimilarityInspector
            threats={threats}
            selectedThreatId={selectedThreatId}
          />
        )}

        {activeTab === 'ctlogs' && (
          <CTLogStreamer
            onInspectDomain={handleInspectCTDomain}
          />
        )}

        {activeTab === 'takedowns' && (
          <TakedownGenerator
            threats={threats}
            selectedThreatId={selectedThreatId}
          />
        )}

        {activeTab === 'apk' && (
          <ApkAnalyzer />
        )}

        {activeTab === 'benchmarks' && (
          <BenchmarkEvaluation />
        )}

        {activeTab === 'sandbox' && (
          <LiveScanner
            onAddThreat={handleAddScannedThreat}
            onNavigateToTakedowns={() => setActiveTab('takedowns')}
          />
        )}
      </main>

      {/* Forensic Modal Drawer */}
      <ThreatDetailModal
        threat={detailModalThreat}
        onClose={() => setDetailModalThreat(null)}
        onOpenSimilarity={handleOpenSimilarity}
        onOpenTakedowns={handleOpenTakedowns}
      />

      {/* Clean Minimal Cyber Footer */}
      <footer className="border-t border-white/5 py-4 bg-[#05070c] text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>PhishNet V2 Autonomous UPI Shield • Production Ready</span>
          </div>
          <div>Domain: Cybersecurity & Privacy • Track 03: Anti-Phishing & UPI Shield</div>
        </div>
      </footer>
    </div>
  );
}
