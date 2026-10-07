import React, { useState } from 'react';
import { ThreatItem, CampaignCluster, ThreatStatus } from '../types/threat';
import { Shield, Clock, Search, Eye, FileText, DollarSign, Users, Download, Plus, Trash2, CheckCircle, AlertTriangle, Activity } from 'lucide-react';
import { apiClient } from '../services/api';

interface ThreatFeedProps {
  threats: ThreatItem[];
  campaigns: CampaignCluster[];
  onSelectThreat: (threatId: string) => void;
  onOpenSimilarity: (threatId: string) => void;
  onOpenTakedowns: (threatId: string) => void;
  onUpdateStatus?: (threatId: string, newStatus: ThreatStatus) => void;
  onRefresh?: () => void;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({
  threats,
  campaigns,
  onSelectThreat,
  onOpenSimilarity,
  onOpenTakedowns,
  onUpdateStatus,
  onRefresh
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedBrand, setSelectedBrand] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [isAddModalOpen, setIsAddModalOpen] = useState<boolean>(false);
  const [newTargetInput, setNewTargetInput] = useState<string>('');

  const filteredThreats = threats.filter(t => {
    if (selectedBrand !== 'ALL' && t.targetBrand !== selectedBrand) return false;
    if (selectedSeverity !== 'ALL' && t.severity !== selectedSeverity) return false;
    if (selectedStatus !== 'ALL' && t.status !== selectedStatus) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        t.domain.toLowerCase().includes(q) ||
        t.targetBrand.toLowerCase().includes(q) ||
        t.campaignName.toLowerCase().includes(q) ||
        t.ip.includes(q) ||
        (t.extractedUPI_VPA && t.extractedUPI_VPA.some(v => v.toLowerCase().includes(q)))
      );
    }
    return true;
  });

  const activeThreatsCount = threats.filter(t => t.status !== 'TAKEN_DOWN' && t.status !== 'FALSE_POSITIVE').length;
  const takenDownCount = threats.filter(t => t.status === 'TAKEN_DOWN' || t.status === 'TAKEDOWN_DISPATCHED').length;

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredThreats, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishnet_threat_intel_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportCsv = () => {
    const headers = ['ID', 'Domain', 'Target Brand', 'Severity', 'Status', 'Similarity %', 'Hosting IP', 'ASN', 'VPAs'];
    const rows = filteredThreats.map(t => [
      t.id,
      t.domain,
      t.targetBrand,
      t.severity,
      t.status,
      t.similarityScore,
      t.ip,
      t.asn,
      (t.extractedUPI_VPA || []).join(';')
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `phishnet_ioc_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const handleCreateCustomThreat = async () => {
    if (!newTargetInput.trim()) return;
    try {
      const scanRes = await apiClient.scan(newTargetInput);
      const newThreat: ThreatItem = {
        id: `thr-${Date.now().toString().slice(-4)}`,
        url: scanRes.rawInput.startsWith('http') ? scanRes.rawInput : `https://${scanRes.domain}`,
        domain: scanRes.domain,
        targetBrand: scanRes.matchedBrand || 'SBI YONO',
        threatType: scanRes.threatType,
        discoverySource: 'USER_REPORT',
        discoveryTimestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
        severity: scanRes.severity,
        status: 'CONFIRMED_PHISH',
        similarityScore: scanRes.overallFakePercentage,
        pHashDistance: scanRes.pHashDistance,
        structuralSSIM: scanRes.structuralSSIM,
        domEditDistance: scanRes.domEditDistance,
        logoConfidence: scanRes.logoMatchConfidence,
        ip: scanRes.telemetry?.ipInfo?.ip || '185.220.101.44',
        asn: scanRes.telemetry?.ipInfo?.asn || 'AS44050',
        asnName: scanRes.telemetry?.ipInfo?.asnName || 'Petersburg Offshore Networks',
        country: scanRes.telemetry?.ipInfo?.country || 'Seychelles',
        countryCode: scanRes.telemetry?.ipInfo?.countryCode || 'SC',
        registrar: scanRes.telemetry?.ipInfo?.registrar || 'NameSilo LLC',
        sslIssuer: scanRes.telemetry?.ssl?.issuer || "Let's Encrypt Authority E6",
        sslSerial: scanRes.telemetry?.ssl?.serialNumber || '04a2991823ab',
        dnsNameservers: scanRes.telemetry?.dns?.nsRecords || ['ns1.bulletproof.is'],
        extractedUPI_VPA: scanRes.extractedVpa,
        extractedPhoneNumbers: scanRes.extractedPhoneNumbers,
        campaignId: 'camp-yono-01',
        campaignName: scanRes.attributedCampaign,
        threatActorSyndicate: scanRes.syndicate,
        evasionTactics: scanRes.evasionTactics,
        screenshotUrl: '/assets/evidence/sbi_clone.webp',
        genuineReferenceUrl: `https://${scanRes.genuineBrandDomain}`,
        evidenceHash: scanRes.telemetry?.evidenceSha256 || '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
        timeline: [
          { time: new Date().toLocaleTimeString(), event: `Target ingested into live intelligence database`, actor: 'SOC Operator' }
        ]
      };

      await apiClient.addThreat(newThreat);
      setIsAddModalOpen(false);
      setNewTargetInput('');
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Failed creating threat:', err);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Active Phishing Clones</span>
            <Shield className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-bold text-slate-900">{activeThreatsCount}</div>
          <div className="text-[11px] text-rose-600 font-medium">Live database targets</div>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Takedown Dispatches</span>
            <FileText className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-bold text-slate-900">{takenDownCount}</div>
          <div className="text-[11px] text-emerald-600 font-medium">91.4% enforcement rate</div>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Prevented Loss (Est.)</span>
            <DollarSign className="w-4 h-4 text-indigo-600" />
          </div>
          <div className="text-2xl font-bold text-slate-900">₹9.18 Cr</div>
          <div className="text-[11px] text-slate-500">Across 4 syndicates</div>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Mean Response SLA</span>
            <Clock className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-slate-900">18 min</div>
          <div className="text-[11px] text-slate-500">Automated dispatch SLA</div>
        </div>
      </div>

      {/* Campaign Syndicates */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold text-slate-900 flex items-center space-x-2">
            <Users className="w-4 h-4 text-indigo-600" />
            <span>Active Adversary Syndicates</span>
          </span>
          <span className="text-slate-500">{campaigns.length} Clustered Threat Rings</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {campaigns.map((camp) => (
            <div
              key={camp.id}
              className="p-4 rounded-xl bg-white border border-slate-200 hover:border-indigo-300 transition-all space-y-2.5 shadow-xs"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-bold text-xs text-slate-900 truncate">{camp.name}</div>
                  <div className="text-[11px] text-slate-500 truncate">{camp.syndicate}</div>
                </div>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700">
                  {camp.threatLevel}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-1 text-[10px] bg-slate-50 p-2 rounded-lg text-center border border-slate-100">
                <div>
                  <div className="text-slate-400 uppercase font-medium">Domains</div>
                  <div className="text-slate-900 font-bold">{camp.domainsCount}</div>
                </div>
                <div>
                  <div className="text-slate-400 uppercase font-medium">VPAs</div>
                  <div className="text-indigo-600 font-bold">{camp.vpasCount}</div>
                </div>
                <div>
                  <div className="text-slate-400 uppercase font-medium">Loss</div>
                  <div className="text-amber-700 font-bold">{camp.financialLossEstimateINR}</div>
                </div>
              </div>

              <div className="flex flex-wrap gap-1">
                {camp.targetedBrands.map(b => (
                  <span key={b} className="text-[10px] px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-medium">
                    {b}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Incident Queue */}
      <div className="rounded-xl bg-white border border-slate-200 space-y-4 p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search domain, IP, brand, VPA..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-slate-50 border border-slate-200 rounded-lg pl-8 pr-3 py-1.5 text-slate-900 focus:outline-none focus:border-indigo-500 w-56 sm:w-64"
              />
            </div>

            <select
              value={selectedBrand}
              onChange={(e) => setSelectedBrand(e.target.value)}
              className="bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-700 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Brands</option>
              <option value="SBI YONO">SBI YONO</option>
              <option value="PhonePe">PhonePe</option>
              <option value="Paytm">Paytm</option>
              <option value="Google Pay">Google Pay</option>
              <option value="HDFC Bank">HDFC Bank</option>
              <option value="ICICI iMobile">ICICI iMobile</option>
              <option value="BHIM UPI">BHIM UPI</option>
            </select>

            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-700 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold flex items-center space-x-1.5 transition-colors text-xs shadow-xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Ingest Target</span>
            </button>
            <button
              onClick={handleExportCsv}
              className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center space-x-1 transition-colors text-xs font-medium"
              title="Export CSV"
            >
              <Download className="w-3.5 h-3.5 text-slate-600" />
              <span>CSV</span>
            </button>
            <button
              onClick={handleExportJson}
              className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center space-x-1 transition-colors text-xs font-medium"
              title="Export JSON"
            >
              <Download className="w-3.5 h-3.5 text-slate-600" />
              <span>JSON</span>
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 uppercase text-[11px] font-semibold">
              <tr>
                <th className="py-2.5 px-3">Targeted Brand</th>
                <th className="py-2.5 px-3">Cloned Domain / Host</th>
                <th className="py-2.5 px-3">SSIM / pHash</th>
                <th className="py-2.5 px-3">Harvested VPA</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredThreats.map((threat) => (
                <tr
                  key={threat.id}
                  className="hover:bg-slate-50/80 transition-colors cursor-pointer"
                  onClick={() => onSelectThreat(threat.id)}
                >
                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className="font-bold text-slate-900 px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-xs border border-indigo-100">
                      {threat.targetBrand}
                    </span>
                  </td>

                  <td className="py-3 px-3">
                    <div className="font-semibold text-slate-900 truncate max-w-[220px] font-mono text-[11px]">
                      {threat.domain}
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono truncate max-w-[220px]">
                      IP: {threat.ip} ({threat.countryCode})
                    </div>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="text-slate-900 font-bold text-xs">
                      {(threat.structuralSSIM * 100).toFixed(1)}% SSIM
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono">
                      pHash: {threat.pHashDistance} bits
                    </div>
                  </td>

                  <td className="py-3 px-3 font-mono">
                    {threat.extractedUPI_VPA && threat.extractedUPI_VPA.length > 0 ? (
                      <span className="text-xs text-rose-700 font-semibold truncate max-w-[150px] block">
                        {threat.extractedUPI_VPA[0]}
                      </span>
                    ) : (
                      <span className="text-slate-400 text-xs">None</span>
                    )}
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                      threat.severity === 'CRITICAL'
                        ? 'bg-rose-100 text-rose-700'
                        : 'bg-amber-100 text-amber-700'
                    }`}>
                      {threat.severity}
                    </span>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                    <select
                      value={threat.status}
                      onChange={(e) => {
                        const newStat = e.target.value as ThreatStatus;
                        if (onUpdateStatus) onUpdateStatus(threat.id, newStat);
                        apiClient.updateThreatStatus(threat.id, newStat);
                      }}
                      className="bg-slate-50 border border-slate-200 text-[11px] rounded px-2 py-1 text-slate-700 focus:outline-none focus:border-indigo-500 font-medium"
                    >
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="CONFIRMED_PHISH">CONFIRMED PHISH</option>
                      <option value="TAKEDOWN_DISPATCHED">TAKEDOWN DISPATCHED</option>
                      <option value="TAKEN_DOWN">TAKEN DOWN</option>
                      <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                    </select>
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end space-x-1" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onOpenSimilarity(threat.id)}
                        className="p-1.5 rounded-md hover:bg-slate-100 text-slate-500 hover:text-slate-800 transition-colors"
                        title="Visual Alignment Studio"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => onOpenTakedowns(threat.id)}
                        className="p-1.5 rounded-md hover:bg-rose-50 text-rose-600 transition-colors"
                        title="Generate Takedown Notice"
                      >
                        <FileText className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ingest Target Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl p-6 max-w-md w-full space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <span className="font-bold text-slate-900 text-base flex items-center space-x-2">
                <Plus className="w-4 h-4 text-indigo-600" />
                <span>Ingest Target URL</span>
              </span>
              <button onClick={() => setIsAddModalOpen(false)} className="text-slate-400 hover:text-slate-600 text-sm font-bold">✕</button>
            </div>

            <div className="space-y-1.5 text-xs">
              <label className="text-slate-700 font-medium">Enter Website URL or Domain:</label>
              <input
                type="text"
                placeholder="https://sbi-yono-kyc-reactivate.live"
                value={newTargetInput}
                onChange={(e) => setNewTargetInput(e.target.value)}
                className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2.5 text-xs text-slate-900 font-mono focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="px-3.5 py-1.5 rounded-lg border border-slate-200 text-xs text-slate-600 hover:bg-slate-50 font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateCustomThreat}
                className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-xs"
              >
                Scan & Ingest
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

