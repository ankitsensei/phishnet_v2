import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { LiveScanner } from './components/LiveScanner';
import { ThreatFeed } from './components/ThreatFeed';
import { CampaignGraph } from './components/CampaignGraph';
import { TakedownGenerator } from './components/TakedownGenerator';
import { BenchmarkEvaluation } from './components/BenchmarkEvaluation';
import { ThreatDetailModal } from './components/ThreatDetailModal';

import { INITIAL_THREATS, INITIAL_CAMPAIGNS, MOCK_GRAPH_DATA } from './data/mockThreats';
import { ThreatItem, ThreatStatus } from './types/threat';
import { ScanResult } from './services/detectionEngine';

export function App() {
  const [activeTab, setActiveTab] = useState<'detector' | 'threats' | 'graph' | 'takedowns' | 'benchmarks'>('detector');
  const [threats, setThreats] = useState<ThreatItem[]>(INITIAL_THREATS);
  const [campaigns] = useState(INITIAL_CAMPAIGNS);
  const [graphData] = useState(MOCK_GRAPH_DATA);
  const [selectedThreatId, setSelectedThreatId] = useState<string>(threats[0]?.id || 'thr-8901');
  const [detailModalThreat, setDetailModalThreat] = useState<ThreatItem | null>(null);

  const activeThreatCount = threats.filter(t => t.status !== 'TAKEN_DOWN' && t.status !== 'FALSE_POSITIVE').length;

  const handleSelectThreat = (threatId: string) => {
    const found = threats.find(t => t.id === threatId);
    if (found) {
      setSelectedThreatId(threatId);
      setDetailModalThreat(found);
    }
  };

  const handleOpenTakedowns = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab('takedowns');
  };

  const handleUpdateStatus = (threatId: string, newStatus: ThreatStatus) => {
    setThreats(prev => prev.map(t => t.id === threatId ? { ...t, status: newStatus } : t));
  };

  const handleAddScannedThreat = (result: ScanResult) => {
    if (!result.isFake) return;

    const newThreat: ThreatItem = {
      id: `thr-${Date.now().toString().slice(-4)}`,
      url: result.rawInput.startsWith('http') ? result.rawInput : `https://${result.domain}`,
      domain: result.domain,
      targetBrand: result.matchedBrand || 'SBI YONO',
      threatType: result.threatType,
      discoverySource: 'USER_REPORT',
      discoveryTimestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
      severity: result.severity,
      status: 'CONFIRMED_PHISH',
      similarityScore: result.overallFakePercentage,
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
      genuineReferenceUrl: `https://${result.genuineBrandDomain}`,
      evidenceHash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
      timeline: [
        { time: new Date().toLocaleTimeString(), event: `Source analyzed: detected ${result.overallFakePercentage}% Fake probability`, actor: 'AI Detection Engine' }
      ]
    };

    setThreats(prev => [newThreat, ...prev]);
    setSelectedThreatId(newThreat.id);
  };

  return (
    <div className="min-h-screen bg-[#000000] text-[#f4f4f5] flex flex-col font-sans selection:bg-white selection:text-black">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        threatCount={activeThreatCount}
      />

      {/* Main Page Area */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'detector' && (
          <LiveScanner
            onAddThreat={handleAddScannedThreat}
            onNavigateToTakedowns={() => setActiveTab('takedowns')}
          />
        )}

        {activeTab === 'threats' && (
          <ThreatFeed
            threats={threats}
            campaigns={campaigns}
            onSelectThreat={handleSelectThreat}
            onOpenSimilarity={() => {}}
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

        {activeTab === 'takedowns' && (
          <TakedownGenerator
            threats={threats}
            selectedThreatId={selectedThreatId}
          />
        )}

        {activeTab === 'benchmarks' && (
          <BenchmarkEvaluation />
        )}
      </main>

      {/* Forensic Modal */}
      <ThreatDetailModal
        threat={detailModalThreat}
        onClose={() => setDetailModalThreat(null)}
        onOpenSimilarity={() => {}}
        onOpenTakedowns={handleOpenTakedowns}
      />

      {/* Minimal Footer */}
      <footer className="border-t border-[#1a1a1e] py-4 bg-[#000000] text-center text-xs text-[#55555c] font-mono">
        <div className="max-w-6xl mx-auto px-4 flex flex-wrap items-center justify-between gap-2">
          <span>PhishNet V2 — Fake UPI & Payment Detection</span>
          <span>Track 03 • Cybersecurity & Privacy</span>
        </div>
      </footer>
    </div>
  );
}
