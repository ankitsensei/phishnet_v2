import React, { useState } from 'react';
import { ThreatItem, CampaignCluster, SeverityLevel, ThreatStatus, TargetBrand } from '../types/threat';
import { ShieldAlert, AlertTriangle, CheckCircle2, Clock, Search, Filter, ArrowUpRight, Eye, FileText, Send, DollarSign, Activity, Users, Shield, RefreshCw } from 'lucide-react';

interface ThreatFeedProps {
  threats: ThreatItem[];
  campaigns: CampaignCluster[];
  onSelectThreat: (threatId: string) => void;
  onOpenSimilarity: (threatId: string) => void;
  onOpenTakedowns: (threatId: string) => void;
  onUpdateStatus: (threatId: string, newStatus: ThreatStatus) => void;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({
  threats,
  campaigns,
  onSelectThreat,
  onOpenSimilarity,
  onOpenTakedowns,
  onUpdateStatus
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedBrand, setSelectedBrand] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');

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

  return (
    <div className="space-y-6">
      {/* Top Operations KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0c1017] border border-rose-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400">
            <span>Active Phishing Clones</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-rose-400 mt-2">{activeThreatsCount}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center space-x-1">
            <span className="text-rose-400 font-semibold">+3 newly discovered</span>
            <span>via CT stream</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0c1017] border border-emerald-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400">
            <span>Successful Takedowns</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-emerald-400 mt-2">{takenDownCount}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center space-x-1">
            <span className="text-emerald-400 font-semibold">91.4% success rate</span>
            <span>in &lt; 2 hours</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0c1017] border border-cyan-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400">
            <span>Prevented Loss (Est.)</span>
            <DollarSign className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-cyan-300 mt-2">₹9.18 Cr</div>
          <div className="text-[11px] text-slate-400 mt-1">Across 4 adversary syndicates</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0c1017] border border-purple-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400">
            <span>Mean Response SLA</span>
            <Clock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-purple-300 mt-2">18 min</div>
          <div className="text-[11px] text-slate-400 mt-1">Automated CERT-In & NPCI dispatch</div>
        </div>
      </div>

      {/* Campaign Syndicates Showcase */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-mono font-bold text-white uppercase flex items-center space-x-2">
            <Users className="w-4 h-4 text-cyan-400" />
            <span>Active Adversary Syndicates & Campaigns</span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            {campaigns.length} Clustered Threat Rings
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {campaigns.map((camp) => (
            <div
              key={camp.id}
              className="p-3.5 rounded-xl bg-[#0d121c] border border-white/10 hover:border-cyan-500/30 transition-all space-y-2"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-bold text-xs text-white truncate">{camp.name}</div>
                  <div className="text-[10px] text-slate-400 font-mono truncate">{camp.syndicate}</div>
                </div>
                <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  {camp.threatLevel}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-1 text-[10px] font-mono bg-[#070a10] p-2 rounded border border-white/5 text-center">
                <div>
                  <div className="text-slate-500">DOMAINS</div>
                  <div className="text-slate-200 font-bold">{camp.domainsCount}</div>
                </div>
                <div>
                  <div className="text-slate-500">VPAs</div>
                  <div className="text-cyan-300 font-bold">{camp.vpasCount}</div>
                </div>
                <div>
                  <div className="text-slate-500">LOSS</div>
                  <div className="text-rose-400 font-bold">{camp.financialLossEstimateINR}</div>
                </div>
              </div>

              <div className="flex flex-wrap gap-1">
                {camp.targetedBrands.map(b => (
                  <span key={b} className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-white/5 text-slate-300">
                    {b}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Threat Incident Queue Table */}
      <div className="rounded-xl bg-[#090d14] border border-white/10 overflow-hidden shadow-2xl space-y-3 p-4">
        {/* Search & Filter Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div className="flex items-center space-x-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search domain, IP, brand, VPA..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-[#141b29] border border-white/10 text-xs rounded-lg pl-8 pr-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono w-64"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Brand Filter */}
            <select
              value={selectedBrand}
              onChange={(e) => setSelectedBrand(e.target.value)}
              className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Brands</option>
              <option value="SBI YONO">SBI YONO</option>
              <option value="PhonePe">PhonePe</option>
              <option value="Paytm">Paytm</option>
              <option value="Google Pay">Google Pay</option>
              <option value="HDFC Bank">HDFC Bank</option>
            </select>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Statuses</option>
              <option value="CONFIRMED_PHISH">Confirmed Phish</option>
              <option value="TAKEDOWN_DISPATCHED">Takedown Dispatched</option>
              <option value="TAKEN_DOWN">Taken Down</option>
              <option value="INVESTIGATING">Investigating</option>
            </select>
          </div>
        </div>

        {/* Incidents Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#101622] text-slate-400 border-b border-white/10 uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-3">Target Brand</th>
                <th className="py-2.5 px-3">Suspicious Domain / URL</th>
                <th className="py-2.5 px-3">SSIM / pHash</th>
                <th className="py-2.5 px-3">Harvested VPA</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Forensic Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredThreats.map((threat) => (
                <tr
                  key={threat.id}
                  className="hover:bg-white/5 transition-colors cursor-pointer"
                  onClick={() => onSelectThreat(threat.id)}
                >
                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className="font-bold text-white px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 text-[11px]">
                      {threat.targetBrand}
                    </span>
                  </td>

                  <td className="py-3 px-3">
                    <div className="font-semibold text-rose-300 truncate max-w-[220px]">
                      {threat.domain}
                    </div>
                    <div className="text-[10px] text-slate-400 truncate max-w-[220px]">
                      IP: {threat.ip} ({threat.countryCode})
                    </div>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="text-cyan-300 font-bold text-xs">
                      {(threat.structuralSSIM * 100).toFixed(1)}% SSIM
                    </div>
                    <div className="text-[10px] text-slate-400">
                      pHash: {threat.pHashDistance} bits
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    {threat.extractedUPI_VPA && threat.extractedUPI_VPA.length > 0 ? (
                      <span className="text-[11px] text-emerald-400 font-mono truncate max-w-[150px] block">
                        {threat.extractedUPI_VPA[0]}
                      </span>
                    ) : (
                      <span className="text-slate-500 text-[10px]">None</span>
                    )}
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                      threat.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                      threat.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                      'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    }`}>
                      {threat.severity}
                    </span>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      threat.status === 'TAKEN_DOWN' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                      threat.status === 'TAKEDOWN_DISPATCHED' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' :
                      'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    }`}>
                      {threat.status.replace('_', ' ')}
                    </span>
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end space-x-1.5" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onOpenSimilarity(threat.id)}
                        className="p-1.5 rounded hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-transparent hover:border-cyan-500/30"
                        title="Visual Diff Studio"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => onOpenTakedowns(threat.id)}
                        className="p-1.5 rounded hover:bg-rose-500/20 text-slate-300 hover:text-rose-300 border border-transparent hover:border-rose-500/30"
                        title="Generate Takedown Notice"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
