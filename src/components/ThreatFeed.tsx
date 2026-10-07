import React, { useState } from 'react';
import { ThreatItem, CampaignCluster, ThreatStatus } from '../types/threat';
import { Shield, Clock, Search, Eye, FileText, DollarSign, Users } from 'lucide-react';

interface ThreatFeedProps {
  threats: ThreatItem[];
  campaigns: CampaignCluster[];
  onSelectThreat: (threatId: string) => void;
  onOpenSimilarity: (threatId: string) => void;
  onOpenTakedowns: (threatId: string) => void;
  onUpdateStatus?: (threatId: string, newStatus: ThreatStatus) => void;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({
  threats,
  campaigns,
  onSelectThreat,
  onOpenSimilarity,
  onOpenTakedowns
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
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="flex items-center justify-between text-[11px] uppercase text-[#71717a]">
            <span>Active Phishing Clones</span>
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div className="text-3xl font-bold text-white mt-1">{activeThreatsCount}</div>
          <div className="text-[10px] text-[#a1a1aa] mt-0.5">Live detected targets</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="flex items-center justify-between text-[11px] uppercase text-[#71717a]">
            <span>Takedown Dispatches</span>
            <FileText className="w-4 h-4 text-white" />
          </div>
          <div className="text-3xl font-bold text-white mt-1">{takenDownCount}</div>
          <div className="text-[10px] text-[#a1a1aa] mt-0.5">91.4% success rate</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="flex items-center justify-between text-[11px] uppercase text-[#71717a]">
            <span>Prevented Loss (Est.)</span>
            <DollarSign className="w-4 h-4 text-white" />
          </div>
          <div className="text-3xl font-bold text-white mt-1">₹9.18 Cr</div>
          <div className="text-[10px] text-[#a1a1aa] mt-0.5">Across 4 syndicates</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="flex items-center justify-between text-[11px] uppercase text-[#71717a]">
            <span>Mean Response SLA</span>
            <Clock className="w-4 h-4 text-white" />
          </div>
          <div className="text-3xl font-bold text-white mt-1">18 min</div>
          <div className="text-[10px] text-[#a1a1aa] mt-0.5">Automated dispatch SLA</div>
        </div>
      </div>

      {/* Campaign Syndicates */}
      <div className="space-y-3 font-mono">
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold text-white uppercase flex items-center space-x-2">
            <Users className="w-4 h-4 text-white" />
            <span>Active Adversary Syndicates</span>
          </span>
          <span className="text-[#71717a]">{campaigns.length} Clustered Threat Rings</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {campaigns.map((camp) => (
            <div
              key={camp.id}
              className="p-3.5 rounded-lg bg-[#09090b] border border-[#27272a] hover:border-white transition-colors space-y-2"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-bold text-xs text-white truncate">{camp.name}</div>
                  <div className="text-[10px] text-[#71717a] truncate">{camp.syndicate}</div>
                </div>
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-[#18181b] border border-[#27272a] text-white">
                  {camp.threatLevel}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-1 text-[10px] bg-[#121214] p-2 rounded text-center">
                <div>
                  <div className="text-[#71717a]">DOMAINS</div>
                  <div className="text-white font-bold">{camp.domainsCount}</div>
                </div>
                <div>
                  <div className="text-[#71717a]">VPAs</div>
                  <div className="text-white font-bold">{camp.vpasCount}</div>
                </div>
                <div>
                  <div className="text-[#71717a]">LOSS</div>
                  <div className="text-white font-bold">{camp.financialLossEstimateINR}</div>
                </div>
              </div>

              <div className="flex flex-wrap gap-1">
                {camp.targetedBrands.map(b => (
                  <span key={b} className="text-[9px] px-1.5 py-0.5 rounded bg-[#121214] border border-[#27272a] text-[#a1a1aa]">
                    {b}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Incident Queue */}
      <div className="rounded-lg bg-[#09090b] border border-[#27272a] space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#27272a] pb-3 font-mono text-xs">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#71717a] absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search domain, IP, brand, VPA..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#121214] border border-[#27272a] rounded pl-8 pr-3 py-1.5 text-white focus:outline-none focus:border-white w-64"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedBrand}
              onChange={(e) => setSelectedBrand(e.target.value)}
              className="bg-[#121214] border border-[#27272a] rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-white"
            >
              <option value="ALL">All Brands</option>
              <option value="SBI YONO">SBI YONO</option>
              <option value="PhonePe">PhonePe</option>
              <option value="Paytm">Paytm</option>
              <option value="Google Pay">Google Pay</option>
              <option value="HDFC Bank">HDFC Bank</option>
            </select>

            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-[#121214] border border-[#27272a] rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-white"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#121214] text-[#a1a1aa] border-b border-[#27272a] uppercase text-[10px]">
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
            <tbody className="divide-y divide-[#18181b]">
              {filteredThreats.map((threat) => (
                <tr
                  key={threat.id}
                  className="hover:bg-[#121214] transition-colors cursor-pointer"
                  onClick={() => onSelectThreat(threat.id)}
                >
                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className="font-bold text-white px-2 py-0.5 rounded bg-[#18181b] border border-[#27272a] text-[11px]">
                      {threat.targetBrand}
                    </span>
                  </td>

                  <td className="py-3 px-3">
                    <div className="font-semibold text-white truncate max-w-[220px]">
                      {threat.domain}
                    </div>
                    <div className="text-[10px] text-[#71717a] truncate max-w-[220px]">
                      IP: {threat.ip} ({threat.countryCode})
                    </div>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="text-white font-bold text-xs">
                      {(threat.structuralSSIM * 100).toFixed(1)}% SSIM
                    </div>
                    <div className="text-[10px] text-[#71717a]">
                      pHash: {threat.pHashDistance} bits
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    {threat.extractedUPI_VPA && threat.extractedUPI_VPA.length > 0 ? (
                      <span className="text-[11px] text-[#d4d4d8] truncate max-w-[150px] block">
                        {threat.extractedUPI_VPA[0]}
                      </span>
                    ) : (
                      <span className="text-[#52525b] text-[10px]">None</span>
                    )}
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#18181b] border border-[#27272a] text-white">
                      {threat.severity}
                    </span>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[10px] text-[#a1a1aa] bg-[#000000] border border-[#27272a]">
                      {threat.status.replace('_', ' ')}
                    </span>
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end space-x-1.5" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onOpenSimilarity(threat.id)}
                        className="p-1.5 rounded hover:bg-[#27272a] text-[#a1a1aa] hover:text-white"
                        title="Visual Diff Studio"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => onOpenTakedowns(threat.id)}
                        className="p-1.5 rounded hover:bg-[#27272a] text-[#a1a1aa] hover:text-white"
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
