import React, { useState, useEffect } from 'react';
import { Radio, Play, Pause, Search, ArrowUpRight, Activity, Sparkles, ShieldAlert, Cpu } from 'lucide-react';
import { CTLogEntry, TargetBrand } from '../types/threat';
import { SAMPLE_CT_LOG_STREAM } from '../data/mockThreats';

interface CTLogStreamerProps {
  onInspectDomain?: (domain: string) => void;
}

const SUSPICIOUS_DOMAINS_SEED = [
  { prefix: 'phonepe-cashback-claim-', tld: '.top', brand: 'PhonePe' as TargetBrand, risk: 96 },
  { prefix: 'sbi-yono-kyc-reactivate-', tld: '.live', brand: 'SBI YONO' as TargetBrand, risk: 98 },
  { prefix: 'paytm-instant-refund-v2-', tld: '.xyz', brand: 'Paytm' as TargetBrand, risk: 94 },
  { prefix: 'gpay-scratch-card-win-', tld: '.online', brand: 'Google Pay' as TargetBrand, risk: 92 },
  { prefix: 'hdfc-netbanking-verify-', tld: '.site', brand: 'HDFC Bank' as TargetBrand, risk: 95 },
  { prefix: 'bhim-upi-reward-portal-', tld: '.link', brand: 'BHIM UPI' as TargetBrand, risk: 91 },
  { prefix: 'icici-imobile-login-update-', tld: '.store', brand: 'ICICI iMobile' as TargetBrand, risk: 93 },
];

const BENIGN_DOMAINS_SEED = [
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

  // High-throughput stream generator
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
        const template = SUSPICIOUS_DOMAINS_SEED[Math.floor(Math.random() * SUSPICIOUS_DOMAINS_SEED.length)];
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
        const randLegit = BENIGN_DOMAINS_SEED[Math.floor(Math.random() * BENIGN_DOMAINS_SEED.length)];
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
    }, 1500);

    return () => clearInterval(interval);
  }, [isPlaying]);

  const filteredStream = stream.filter(item => {
    if (filterBrand !== 'ALL' && item.matchedBrand !== filterBrand) return false;
    if (searchQuery.trim() && !item.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      {/* Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">Total Certificates</div>
          <div className="text-2xl font-bold text-slate-900">{totalProcessed.toLocaleString()}</div>
          <div className="text-[11px] text-indigo-600 flex items-center space-x-1.5 font-medium">
            <span className="w-2 h-2 rounded-full bg-indigo-600 animate-pulse" />
            <span>CertStream active feed</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">Flagged Typosquats</div>
          <div className="text-2xl font-bold text-rose-600">{flaggedCount.toLocaleString()}</div>
          <div className="text-[11px] text-rose-700 font-medium">Deceptive brand names</div>
        </div>

        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">Stream Velocity</div>
          <div className="text-2xl font-bold text-slate-900">48 / sec</div>
          <div className="text-[11px] text-emerald-600 font-medium">Real-time log crawler</div>
        </div>

        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">Detection Latency</div>
          <div className="text-2xl font-bold text-slate-900">38 ms</div>
          <div className="text-[11px] text-slate-500">Issuance to alert SLA</div>
        </div>
      </div>

      {/* Control Toolbar */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 flex flex-wrap items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              isPlaying
                ? 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                : 'bg-indigo-600 text-white hover:bg-indigo-700 shadow-xs'
            }`}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5 text-amber-600" /> : <Play className="w-3.5 h-3.5 text-white" />}
            <span>{isPlaying ? 'Pause Stream' : 'Resume Stream'}</span>
          </button>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter domain name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-50 border border-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 text-slate-900 focus:outline-none focus:border-indigo-500 w-56 font-mono"
            />
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs">
          <span className="text-slate-600 font-medium">Brand Filter:</span>
          <select
            value={filterBrand}
            onChange={(e) => setFilterBrand(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-xs rounded-lg px-2.5 py-1.5 text-slate-700 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Certificates</option>
            <option value="PhonePe">PhonePe</option>
            <option value="SBI YONO">SBI YONO</option>
            <option value="Paytm">Paytm</option>
            <option value="Google Pay">Google Pay</option>
            <option value="HDFC Bank">HDFC Bank</option>
            <option value="ICICI iMobile">ICICI iMobile</option>
            <option value="BHIM UPI">BHIM UPI</option>
            <option value="Axis Bank">Axis Bank</option>
          </select>
        </div>
      </div>

      {/* Stream Table */}
      <div className="rounded-xl bg-white border border-slate-200 overflow-hidden shadow-xs">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 uppercase text-[11px] font-semibold">
            <tr>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Discovered Hostname</th>
              <th className="py-2.5 px-3">CA Issuer</th>
              <th className="py-2.5 px-3">Targeted Entity</th>
              <th className="py-2.5 px-3">Risk %</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {filteredStream.map((item) => (
              <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                <td className="py-3 px-3 text-slate-500 font-mono text-[11px] whitespace-nowrap">{item.timestamp}</td>
                <td className="py-3 px-3 font-mono font-medium text-slate-900">{item.domain}</td>
                <td className="py-3 px-3 text-slate-600 truncate max-w-[140px]">{item.issuer}</td>
                <td className="py-3 px-3">
                  {item.matchedBrand ? (
                    <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-xs font-semibold">
                      {item.matchedBrand}
                    </span>
                  ) : (
                    <span className="text-slate-400 text-xs">Clean</span>
                  )}
                </td>
                <td className="py-3 px-3 font-bold">
                  <span className={`px-2 py-0.5 rounded-full text-[11px] font-bold ${
                    item.riskScore > 70 ? 'text-rose-700 bg-rose-100' : 'text-emerald-700 bg-emerald-100'
                  }`}>
                    {item.riskScore}%
                  </span>
                </td>
                <td className="py-3 px-3 text-right whitespace-nowrap">
                  {item.isFlagged ? (
                    <button
                      onClick={() => onInspectDomain && onInspectDomain(item.domain)}
                      className="px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-700 text-white font-semibold text-xs inline-flex items-center space-x-1 transition-colors"
                    >
                      <span>Analyze</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  ) : (
                    <span className="text-emerald-600 text-xs font-medium">Passed</span>
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

