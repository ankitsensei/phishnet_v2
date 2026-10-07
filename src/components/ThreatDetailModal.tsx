import React from 'react';
import { ThreatItem } from '../types/threat';
import { ShieldAlert, Globe, Server, Lock, ExternalLink, Calendar, CheckCircle2, Clock, Send, Eye, FileText } from 'lucide-react';

interface ThreatDetailModalProps {
  threat: ThreatItem | null;
  onClose: () => void;
  onOpenSimilarity: (threatId: string) => void;
  onOpenTakedowns: (threatId: string) => void;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  threat,
  onClose,
  onOpenSimilarity,
  onOpenTakedowns
}) => {
  if (!threat) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl bg-[#0b0f17] border border-cyan-500/30 shadow-2xl text-xs text-slate-300">
        {/* Header */}
        <div className="sticky top-0 z-10 px-6 py-4 bg-[#0e1420]/95 backdrop-blur-md border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg ${
              threat.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
              'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-white font-display">Incident Forensics #{threat.id}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                  {threat.severity}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {threat.status.replace('_', ' ')}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                Target: <strong className="text-white">{threat.targetBrand}</strong> • Discovered: {threat.discoveryTimestamp} ({threat.discoverySource})
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Target URL banner */}
          <div className="p-3.5 rounded-xl bg-[#06090e] border border-white/10 font-mono flex items-center justify-between">
            <div className="truncate">
              <span className="text-slate-500">Target URL: </span>
              <span className="text-rose-300 font-semibold">{threat.url}</span>
            </div>
            <a
              href={threat.url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center space-x-1 ml-2"
            >
              <span>Sandbox Open</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          {/* Metric Telemetry Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-[#0f1522] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase font-mono">Visual SSIM Match</div>
              <div className="text-lg font-bold font-mono text-cyan-300 mt-1">{(threat.structuralSSIM * 100).toFixed(1)}%</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0f1522] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase font-mono">pHash Distance</div>
              <div className="text-lg font-bold font-mono text-rose-400 mt-1">{threat.pHashDistance} bits</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0f1522] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase font-mono">Logo OCR Confidence</div>
              <div className="text-lg font-bold font-mono text-amber-300 mt-1">{threat.logoConfidence}%</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0f1522] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase font-mono">Attributed Syndicate</div>
              <div className="text-xs font-bold font-mono text-purple-300 mt-1 truncate">{threat.threatActorSyndicate}</div>
            </div>
          </div>

          {/* Infrastructure & Network Mapping */}
          <div className="p-4 rounded-xl bg-[#0f1522] border border-white/5 space-y-3">
            <div className="font-mono font-bold text-xs text-white uppercase flex items-center space-x-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Hosting & Network Telemetry</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
              <div className="space-y-1.5">
                <div><span className="text-slate-500">Domain Registrar:</span> <span className="text-slate-200">{threat.registrar}</span></div>
                <div><span className="text-slate-500">Host IP:</span> <span className="text-slate-200">{threat.ip} ({threat.country})</span></div>
                <div><span className="text-slate-500">ASN:</span> <span className="text-slate-200">{threat.asn} — {threat.asnName}</span></div>
              </div>
              <div className="space-y-1.5">
                <div><span className="text-slate-500">SSL Issuer:</span> <span className="text-slate-200">{threat.sslIssuer}</span></div>
                <div><span className="text-slate-500">SSL Serial:</span> <span className="text-slate-200">{threat.sslSerial}</span></div>
                <div><span className="text-slate-500">Nameservers:</span> <span className="text-slate-200">{threat.dnsNameservers.join(', ')}</span></div>
              </div>
            </div>
          </div>

          {/* Harvested Payment Handles & Phones */}
          <div className="p-4 rounded-xl bg-[#0f1522] border border-white/5 space-y-3 font-mono">
            <div className="font-bold text-xs text-rose-400 uppercase flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>Harvested Fraud & Payment Vectors</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <div className="text-slate-500 text-[10px] uppercase mb-1">Identified Malicious UPI VPAs:</div>
                <div className="space-y-1">
                  {threat.extractedUPI_VPA?.map(vpa => (
                    <div key={vpa} className="p-1.5 rounded bg-rose-950/20 border border-rose-500/30 text-rose-300">
                      {vpa}
                    </div>
                  )) || <div className="text-slate-500">None extracted</div>}
                </div>
              </div>

              <div>
                <div className="text-slate-500 text-[10px] uppercase mb-1">Associated Scam Phone Numbers:</div>
                <div className="space-y-1">
                  {threat.extractedPhoneNumbers?.map(ph => (
                    <div key={ph} className="p-1.5 rounded bg-amber-950/20 border border-amber-500/30 text-amber-300">
                      {ph}
                    </div>
                  )) || <div className="text-slate-500">None extracted</div>}
                </div>
              </div>
            </div>
          </div>

          {/* Audit Timeline */}
          <div className="p-4 rounded-xl bg-[#0f1522] border border-white/5 space-y-3 font-mono">
            <div className="font-bold text-xs text-slate-300 uppercase flex items-center space-x-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span>Forensic Incident Audit Trail</span>
            </div>
            <div className="space-y-2 border-l border-white/10 ml-2 pl-4">
              {threat.timeline.map((event, idx) => (
                <div key={idx} className="relative text-xs">
                  <span className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-cyan-400" />
                  <div className="flex items-center space-x-2">
                    <span className="text-cyan-400 font-bold">{event.time}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-white/5 text-slate-400">{event.actor}</span>
                  </div>
                  <div className="text-slate-300 mt-0.5">{event.event}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Action Bar */}
          <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-white/10">
            <div className="text-[11px] font-mono text-slate-400">
              Evidence Digest: SHA256({threat.evidenceHash.slice(0, 16)}...)
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => {
                  onClose();
                  onOpenSimilarity(threat.id);
                }}
                className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-medium flex items-center space-x-1.5"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Visual Studio</span>
              </button>

              <button
                onClick={() => {
                  onClose();
                  onOpenTakedowns(threat.id);
                }}
                className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-lg shadow-rose-600/30"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Generate Takedown Notice</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
