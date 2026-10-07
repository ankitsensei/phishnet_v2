import React, { useState, useEffect } from 'react';
import { Radio, Play, Pause, Search, ArrowUpRight, Activity } from 'lucide-react';
import { CTLogEntry, TargetBrand } from '../types/threat';
import { SAMPLE_CT_LOG_STREAM } from '../data/mockThreats';

interface CTLogStreamerProps {
  onInspectDomain?: (domain: string) => void;
}

export const CTLogStreamer: React.FC<CTLogStreamerProps> = ({ onInspectDomain }) => {
  const [stream, setStream] = useState<CTLogEntry[]>(SAMPLE_CT_LOG_STREAM);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [filterBrand, setFilterBrand] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [totalProcessed, setTotalProcessed] = useState<number>(14290);
  const [flaggedCount, setFlaggedCount] = useState<number>(312);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  useEffect(() => {
    let eventSource: EventSource | null = null;

    if (isPlaying) {
      try {
        eventSource = new EventSource('/api/ct/stream');
        
        eventSource.onopen = () => {
          setIsConnected(true);
        };

        eventSource.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.initialBatch) {
              setStream(data.initialBatch);
              if (data.stats) {
                setTotalProcessed(data.stats.totalProcessed);
                setFlaggedCount(data.stats.flaggedCount);
              }
            } else if (data.entry) {
              setStream(prev => [data.entry, ...prev.slice(0, 59)]);
              if (data.stats) {
                setTotalProcessed(data.stats.totalProcessed);
                setFlaggedCount(data.stats.flaggedCount);
              }
            }
          } catch {}
        };

        eventSource.onerror = () => {
          setIsConnected(false);
          eventSource?.close();
        };
      } catch {
        setIsConnected(false);
      }
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
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
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
          <div className="text-[11px] uppercase text-[#71717a]">Total Certificates</div>
          <div className="text-xl font-bold text-white mt-1">{totalProcessed.toLocaleString()}</div>
          <div className="text-[10px] text-[#71717a] flex items-center space-x-1 mt-0.5">
            <span className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-white' : 'bg-[#71717a]'}`} />
            <span>{isConnected ? 'Live CertStream feed' : 'Simulated Stream'}</span>
          </div>
        </div>
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
          <div className="text-[11px] uppercase text-[#71717a]">Flagged Typosquats</div>
          <div className="text-xl font-bold text-white mt-1">{flaggedCount.toLocaleString()}</div>
          <div className="text-[10px] text-[#71717a]">Deceptive brand tokens</div>
        </div>
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
          <div className="text-[11px] uppercase text-[#71717a]">Stream Velocity</div>
          <div className="text-xl font-bold text-white mt-1">48 / sec</div>
          <div className="text-[10px] text-[#71717a]">Real-time CT log ingestion</div>
        </div>
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
          <div className="text-[11px] uppercase text-[#71717a]">Detection Latency</div>
          <div className="text-xl font-bold text-white mt-1">38 ms</div>
          <div className="text-[10px] text-[#71717a]">Issuance to trigger</div>
        </div>
      </div>

      {/* Control Toolbar */}
      <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226] flex flex-wrap items-center justify-between gap-3">
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
              className="bg-[#121214] border border-[#222226] text-xs rounded pl-8 pr-3 py-1.5 text-white focus:outline-none focus:border-white font-mono w-56"
            />
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-[#71717a] font-mono">Brand Filter:</span>
          <select
            value={filterBrand}
            onChange={(e) => setFilterBrand(e.target.value)}
            className="bg-[#121214] border border-[#222226] text-xs rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-white font-mono"
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
            <option value="Cred">Cred</option>
            <option value="Amazon Pay">Amazon Pay</option>
          </select>
        </div>
      </div>

      {/* Stream Table */}
      <div className="rounded-lg bg-[#09090b] border border-[#222226] overflow-hidden">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#121214] text-[#a1a1aa] border-b border-[#222226] uppercase text-[10px]">
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
                    <span className="px-2 py-0.5 rounded bg-[#18181b] border border-[#222226] text-white text-[10px]">
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
                      className="px-2.5 py-1 rounded bg-white text-black font-semibold text-[10px] inline-flex items-center space-x-1 hover:bg-[#e4e4e7] transition-colors"
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
