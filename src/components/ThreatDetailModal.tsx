import React from 'react';
import { ThreatItem } from '../types/threat';
import { Shield, Server, ExternalLink, Clock, Eye, FileText, AlertTriangle, CheckCircle2 } from 'lucide-react';

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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl bg-white border border-slate-200 text-xs text-slate-700 shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 z-10 px-6 py-4 bg-white/95 border-b border-slate-200 flex items-center justify-between backdrop-blur-md">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-rose-50 border border-rose-100 text-rose-600 font-bold shadow-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-base font-bold text-slate-900">Incident Forensics #{threat.id}</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200">
                  {threat.severity}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                  {threat.status.replace('_', ' ')}
                </span>
              </div>
              <div className="text-xs text-slate-500 mt-0.5">
                Target: <strong className="text-indigo-600 font-semibold">{threat.targetBrand}</strong> • Discovered: {threat.discoveryTimestamp}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-500 hover:text-slate-800 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5">
          {/* Target URL */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between">
            <div className="truncate font-mono text-xs">
              <span className="text-slate-500 font-sans">Target URL: </span>
              <span className="text-indigo-700 font-semibold">{threat.url}</span>
            </div>
            <a
              href={threat.url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-indigo-600 hover:text-indigo-700 flex items-center space-x-1 ml-3 underline font-semibold shrink-0"
            >
              <span>View Target</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          {/* Metric Telemetry */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <div className="text-indigo-700 text-[10px] uppercase font-bold">Visual SSIM</div>
              <div className="text-2xl font-bold text-slate-900 mt-1">{(threat.structuralSSIM * 100).toFixed(1)}%</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <div className="text-blue-700 text-[10px] uppercase font-bold">pHash Hamming</div>
              <div className="text-2xl font-bold text-slate-900 mt-1">{threat.pHashDistance} bits</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <div className="text-rose-700 text-[10px] uppercase font-bold">OCR Logo Match</div>
              <div className="text-2xl font-bold text-slate-900 mt-1">{threat.logoConfidence}%</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <div className="text-emerald-700 text-[10px] uppercase font-bold">Syndicate</div>
              <div className="text-xs font-bold text-slate-900 mt-1 truncate">{threat.threatActorSyndicate}</div>
            </div>
          </div>

          {/* Network & Infrastructure */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="font-bold text-xs text-slate-900 uppercase flex items-center space-x-2">
              <Server className="w-4 h-4 text-indigo-600" />
              <span>Hosting & Network Telemetry</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="space-y-1.5">
                <div><span className="text-slate-500">Registrar:</span> <span className="text-slate-800 font-medium">{threat.registrar}</span></div>
                <div><span className="text-slate-500">Host IP:</span> <span className="text-slate-800 font-mono font-medium">{threat.ip} ({threat.country})</span></div>
                <div><span className="text-slate-500">ASN:</span> <span className="text-slate-800 font-mono">{threat.asn} — {threat.asnName}</span></div>
              </div>
              <div className="space-y-1.5">
                <div><span className="text-slate-500">SSL Issuer:</span> <span className="text-slate-800">{threat.sslIssuer}</span></div>
                <div><span className="text-slate-500">SSL Serial:</span> <span className="text-slate-800 font-mono">{threat.sslSerial}</span></div>
                <div><span className="text-slate-500">Nameservers:</span> <span className="text-slate-800 font-mono">{threat.dnsNameservers.join(', ')}</span></div>
              </div>
            </div>
          </div>

          {/* Harvested VPAs & Phones */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="font-bold text-xs text-slate-900 uppercase flex items-center space-x-2">
              <Shield className="w-4 h-4 text-rose-600" />
              <span>Harvested Fraud & Payment Vectors</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <div className="text-slate-500 text-[10px] uppercase font-bold mb-1.5">Identified Malicious UPI VPAs:</div>
                <div className="space-y-1.5">
                  {threat.extractedUPI_VPA?.map(vpa => (
                    <div key={vpa} className="p-2 rounded-lg bg-white border border-rose-200 text-rose-700 font-mono font-semibold">
                      {vpa}
                    </div>
                  )) || <div className="text-slate-500">None</div>}
                </div>
              </div>

              <div>
                <div className="text-slate-500 text-[10px] uppercase font-bold mb-1.5">Associated Scam Phone Numbers:</div>
                <div className="space-y-1.5">
                  {threat.extractedPhoneNumbers?.map(ph => (
                    <div key={ph} className="p-2 rounded-lg bg-white border border-amber-200 text-amber-800 font-mono font-semibold">
                      {ph}
                    </div>
                  )) || <div className="text-slate-500">None</div>}
                </div>
              </div>
            </div>
          </div>

          {/* Audit Timeline */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="font-bold text-xs text-slate-900 uppercase flex items-center space-x-2">
              <Clock className="w-4 h-4 text-emerald-600" />
              <span>Incident Audit Log</span>
            </div>
            <div className="space-y-2 border-l border-slate-200 ml-2 pl-4">
              {threat.timeline.map((event, idx) => (
                <div key={idx} className="relative text-xs">
                  <span className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-indigo-600 ring-4 ring-white" />
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-900 font-bold">{event.time}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-white text-indigo-700 border border-slate-200 font-medium">{event.actor}</span>
                  </div>
                  <div className="text-slate-600 mt-0.5">{event.event}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Action Bar */}
          <div className="pt-3 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200">
            <div className="text-xs text-slate-500 font-mono">
              Digest: <span className="text-slate-800 font-semibold">SHA256({threat.evidenceHash.slice(0, 16)}...)</span>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => {
                  onClose();
                  onOpenSimilarity(threat.id);
                }}
                className="px-4 py-2 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs font-semibold flex items-center space-x-1.5 transition-all shadow-sm"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Visual Studio</span>
              </button>

              <button
                onClick={() => {
                  onClose();
                  onOpenTakedowns(threat.id);
                }}
                className="px-5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs flex items-center space-x-1.5 shadow-sm transition-all"
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
