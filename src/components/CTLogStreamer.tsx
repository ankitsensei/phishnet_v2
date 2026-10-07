import React, { useState, useEffect } from 'react';
import { Radio, Play, Pause, Search, ArrowUpRight } from 'lucide-react';
import { CTLogEntry, TargetBrand } from '../types/threat';
import { SAMPLE_CT_LOG_STREAM } from '../data/mockThreats';

interface CTLogStreamerProps {
  onInspectDomain?: (domain: string) => void;
}

const SUSPICIOUS_DOMAIN_GENERATOR = [
  { prefix: 'phonepe-cashback-claim-', tld: '.top', brand: 'PhonePe' as TargetBrand, risk: 96 },
  { prefix: 'sbi-yono-kyc-reactivate-', tld: '.live', brand: 'SBI YONO' as TargetBrand, risk: 98 },
  { prefix: 'paytm-instant-refund-v2-', tld: '.xyz', brand: 'Paytm' as TargetBrand, risk: 94 },
  { prefix: 'gpay-scratch-card-win-', tld: '.online', brand: 'Google Pay' as TargetBrand, risk: 92 },
  { prefix: 'hdfc-netbanking-verify-', tld: '.site', brand: 'HDFC Bank' as TargetBrand, risk: 95 },
  { prefix: 'bhim-upi-reward-portal-', tld: '.link', brand: 'BHIM UPI' as TargetBrand, risk: 91 },
  { prefix: 'icici-imobile-login-update-', tld: '.store', brand: 'ICICI iMobile' as TargetBrand, risk: 93 },
];

const LEGITIMATE_DOMAIN_SAMPLES = [
  'api.github.com', 'us-east-1.amazonaws.com', 'cdn.segment.io',
  'datadoghq.com', 'stripe-assets.com', 'auth.okta.com',
  'slack-edge.com', 'cdn.jsdelivr.net', 'internal.shopify.io'
];

export const CTLogStreamer: React.FC<CTLogStreamerProps> = ({ onInspectDomain }) => {
  const [stream, setStream] = useState<CTLogEntry[]>(SAMPLE_CT_LOG_STREAM);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [filterBrand, setFilterBrand] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [totalProcessed, setTotalProcessed] = useState<number>(14290);
  const [flaggedCount, setFlaggedCount] = useState<number>(312);

  useEffect(() => {
    if (!isPlaying) return;

    const interval = setInterval(() => {
      setTotalProcessed(prev => prev + 1);

      const isSuspicious = Math.random() < 0.35;
      const now = new Date();
      const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
      const randomHex = Math.random().toString(16).substring(2, 6);

      let newEntry: CTLogEntry;
      if (isSuspicious) {
        const template = SUSPICIOUS_DOMAIN_GENERATOR[Math.floor(Math.random() * SUSPICIOUS_DOMAIN_GENERATOR.length)];
        const domain = `${template.prefix}${Math.floor(Math.random() * 900 + 100)}${template.tld}`;
        setFlaggedCount(prev => prev + 1);
        newEntry = {
          id: `ct-${Date.now()}-${randomHex}`,
          domain,
          issuer: "Let's Encrypt Authority E6",
          timestamp: timeStr,
          matchedBrand: template.brand,
          riskScore: template.risk,
          isFlagged: true,
          fingerprint: `SHA256:${randomHex}..${Math.random().toString(16).substring(2, 6)}`
        };
      } else {
        const randLegit = LEGITIMATE_DOMAIN_SAMPLES[Math.floor(Math.random() * LEGITIMATE_DOMAIN_SAMPLES.length)];
        const domain = `${randomHex}.${randLegit}`;
        newEntry = {
          id: `ct-${Date.now()}-${randomHex}`,
          domain,
          issuer: 'DigiCert Global Root G2',
          timestamp: timeStr,
          riskScore: Math.floor(Math.random() * 5),
          isFlagged: false,
          fingerprint: `SHA256:${randomHex}..${Math.random().toString(16).substring(2, 6)}`
        };
      }

      setStream(prev => [newEntry, ...prev.slice(0, 49)]);
    }, 1400);

    return () => clearInterval(interval);
  }, [isPlaying]);

  const filteredStream = stream.filter(item => {
    if (filterBrand !== 'ALL' && item.matchedBrand !== filterBrand) return false;
    if (searchQuery.trim() && !item.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Total Certificates</div>
          <div className="text-xl font-bold text-white mt-1">{totalProcessed.toLocaleString()}</div>
          <div className="text-[10px] text-[#71717a]">CertStream ingest stream</div>
        </div>
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Flagged Typosquats</div>
          <div className="text-xl font-bold text-white mt-1">{flaggedCount.toLocaleString()}</div>
          <div className="text-[10px] text-[#71717a]">Deceptive brand tokens</div>
        </div>
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Stream Velocity</div>
          <div className="text-xl font-bold text-white mt-1">42 / sec</div>
          <div className="text-[10px] text-[#71717a]">Real-time ingestion rate</div>
        </div>
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Processing Latency</div>
          <div className="text-xl font-bold text-white mt-1">42 ms</div>
          <div className="text-[10px] text-[#71717a]">Issuance to detection</div>
        </div>
      </div>

      {/* Control Toolbar */}
      <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors ${
              isPlaying
                ? 'bg-[#18181b] text-white border border-[#3f3f46]'
                : 'bg-white text-black font-semibold'
            }`}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isPlaying ? 'Pause Stream' : 'Resume Stream'}</span>
          </button>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#71717a] absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter domain name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#121214] border border-[#27272a] text-xs rounded pl-8 pr-3 py-1.5 text-white focus:outline-none focus:border-white font-mono w-56"
            />
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-[#71717a] font-mono">Brand:</span>
          <select
            value={filterBrand}
            onChange={(e) => setFilterBrand(e.target.value)}
            className="bg-[#121214] border border-[#27272a] text-xs rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-white font-mono"
          >
            <option value="ALL">All Certificates</option>
            <option value="PhonePe">PhonePe</option>
            <option value="SBI YONO">SBI YONO</option>
            <option value="Paytm">Paytm</option>
            <option value="Google Pay">Google Pay</option>
            <option value="HDFC Bank">HDFC Bank</option>
            <option value="BHIM UPI">BHIM UPI</option>
          </select>
        </div>
      </div>

      {/* Stream Table */}
      <div className="rounded-lg bg-[#09090b] border border-[#27272a] overflow-hidden">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#121214] text-[#a1a1aa] border-b border-[#27272a] uppercase text-[10px]">
            <tr>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Discovered Hostname</th>
              <th className="py-2.5 px-3">CA Issuer</th>
              <th className="py-2.5 px-3">Targeted Entity</th>
              <th className="py-2.5 px-3">Fake Risk %</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#18181b]">
            {filteredStream.map((item) => (
              <tr key={item.id} className="hover:bg-[#121214] transition-colors">
                <td className="py-2.5 px-3 text-[#71717a] whitespace-nowrap">{item.timestamp}</td>
                <td className="py-2.5 px-3 font-semibold text-white">{item.domain}</td>
                <td className="py-2.5 px-3 text-[#a1a1aa] truncate max-w-[140px]">{item.issuer}</td>
                <td className="py-2.5 px-3">
                  {item.matchedBrand ? (
                    <span className="px-2 py-0.5 rounded bg-[#18181b] border border-[#27272a] text-white text-[10px]">
                      {item.matchedBrand}
                    </span>
                  ) : (
                    <span className="text-[#52525b] text-[10px]">Clean</span>
                  )}
                </td>
                <td className="py-2.5 px-3 font-bold text-white">{item.riskScore}%</td>
                <td className="py-2.5 px-3 text-right whitespace-nowrap">
                  {item.isFlagged ? (
                    <button
                      onClick={() => onInspectDomain && onInspectDomain(item.domain)}
                      className="px-2.5 py-1 rounded bg-white text-black font-semibold text-[10px] inline-flex items-center space-x-1"
                    >
                      <span>Analyze</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </button>
                  ) : (
                    <span className="text-[#52525b] text-[10px]">Passed</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
