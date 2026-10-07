import React, { useState, useEffect } from 'react';
import { Radio, Play, Pause, Search, ShieldAlert, CheckCircle2, ArrowUpRight, Zap, RefreshCw, Filter } from 'lucide-react';
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
  const [velocity, setVelocity] = useState<number>(42);

  // Live streaming effect
  useEffect(() => {
    if (!isPlaying) return;

    const interval = setInterval(() => {
      setTotalProcessed(prev => prev + 1);

      // Randomly spawn a suspicious or legitimate log
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
      {/* Metrics Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-[#0d121c] border border-cyan-500/20">
          <div className="text-[11px] uppercase font-mono text-slate-400">Total Certs Processed</div>
          <div className="text-xl font-bold font-mono text-cyan-300 mt-1">{totalProcessed.toLocaleString()}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">CertStream / CT Log WebSocket</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#0d121c] border border-rose-500/20">
          <div className="text-[11px] uppercase font-mono text-slate-400">Flagged Typosquats</div>
          <div className="text-xl font-bold font-mono text-rose-400 mt-1">{flaggedCount.toLocaleString()}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">High Brand Entropy & Threat TLDs</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#0d121c] border border-emerald-500/20">
          <div className="text-[11px] uppercase font-mono text-slate-400">Ingest Velocity</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-1">{velocity} / sec</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Real-time throughput</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#0d121c] border border-purple-500/20">
          <div className="text-[11px] uppercase font-mono text-slate-400">Detection Latency</div>
          <div className="text-xl font-bold font-mono text-purple-300 mt-1">42ms</div>
          <div className="text-[10px] text-slate-500 mt-0.5">From Cert issuance to Flag</div>
        </div>
      </div>

      {/* Control Bar */}
      <div className="p-3.5 rounded-xl bg-[#0d121c] border border-white/10 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              isPlaying
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 hover:bg-rose-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30'
            }`}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isPlaying ? 'Pause Stream' : 'Resume Stream'}</span>
          </button>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search domain or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#141b29] border border-white/10 text-xs rounded-lg pl-8 pr-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono w-56"
            />
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Filter Brand:</span>
          <select
            value={filterBrand}
            onChange={(e) => setFilterBrand(e.target.value)}
            className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Certificates</option>
            <option value="PhonePe">PhonePe</option>
            <option value="SBI YONO">SBI YONO</option>
            <option value="Paytm">Paytm</option>
            <option value="Google Pay">Google Pay</option>
            <option value="HDFC Bank">HDFC Bank</option>
            <option value="BHIM UPI">BHIM UPI</option>
            <option value="ICICI iMobile">ICICI iMobile</option>
          </select>
        </div>
      </div>

      {/* Stream Table */}
      <div className="rounded-xl bg-[#090d14] border border-white/10 overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#101622] text-slate-400 border-b border-white/10 uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Discovered Domain</th>
                <th className="py-2.5 px-3">CA Issuer</th>
                <th className="py-2.5 px-3">Targeted Brand</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredStream.map((item) => (
                <tr
                  key={item.id}
                  className={`hover:bg-white/5 transition-colors ${
                    item.isFlagged ? 'bg-rose-950/20' : ''
                  }`}
                >
                  <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                    {item.timestamp}
                  </td>
                  <td className="py-2.5 px-3 font-semibold">
                    <span className={item.isFlagged ? 'text-rose-300' : 'text-slate-300'}>
                      {item.domain}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px] truncate max-w-[140px]">
                    {item.issuer}
                  </td>
                  <td className="py-2.5 px-3">
                    {item.matchedBrand ? (
                      <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[10px] font-bold">
                        {item.matchedBrand}
                      </span>
                    ) : (
                      <span className="text-slate-500 text-[10px]">None (Benign)</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-12 bg-white/5 h-1.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            item.riskScore >= 90 ? 'bg-rose-500' :
                            item.riskScore >= 70 ? 'bg-amber-500' : 'bg-emerald-500'
                          }`}
                          style={{ width: `${item.riskScore}%` }}
                        />
                      </div>
                      <span className={`text-[11px] font-bold ${
                        item.riskScore >= 90 ? 'text-rose-400' :
                        item.riskScore >= 70 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {item.riskScore}
                      </span>
                    </div>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {item.isFlagged ? (
                      <button
                        onClick={() => onInspectDomain && onInspectDomain(item.domain)}
                        className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-[10px] font-bold flex items-center space-x-1"
                      >
                        <span>Deep Scan</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    ) : (
                      <span className="text-slate-500 text-[10px]">Passed</span>
                    )}
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
