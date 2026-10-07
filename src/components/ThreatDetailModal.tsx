import React from 'react';
import { ThreatItem } from '../types/threat';
import { Shield, Server, ExternalLink, Clock, Eye, FileText } from 'lucide-react';

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
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-lg bg-[#09090b] border border-[#27272a] text-xs text-[#d4d4d8] font-mono">
        {/* Header */}
        <div className="sticky top-0 z-10 px-6 py-4 bg-[#09090b] border-b border-[#27272a] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded bg-white text-black font-bold">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-white">Incident Forensics #{threat.id}</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-[#18181b] text-white border border-[#27272a]">
                  {threat.severity}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#000000] text-[#a1a1aa] border border-[#27272a]">
                  {threat.status.replace('_', ' ')}
                </span>
              </div>
              <div className="text-[11px] text-[#71717a] mt-0.5">
                Target: <strong className="text-white">{threat.targetBrand}</strong> • Discovered: {threat.discoveryTimestamp}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded bg-[#18181b] hover:bg-[#27272a] text-[#a1a1aa] hover:text-white"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Target URL */}
          <div className="p-3.5 rounded bg-[#000000] border border-[#27272a] flex items-center justify-between">
            <div className="truncate">
              <span className="text-[#71717a]">Target URL: </span>
              <span className="text-white font-semibold">{threat.url}</span>
            </div>
            <a
              href={threat.url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-[#a1a1aa] hover:text-white flex items-center space-x-1 ml-2 underline"
            >
              <span>View Target</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          {/* Metric Telemetry */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded bg-[#121214] border border-[#27272a]">
              <div className="text-[#71717a] text-[10px] uppercase">Visual SSIM</div>
              <div className="text-lg font-bold text-white mt-1">{(threat.structuralSSIM * 100).toFixed(1)}%</div>
            </div>
            <div className="p-3 rounded bg-[#121214] border border-[#27272a]">
              <div className="text-[#71717a] text-[10px] uppercase">pHash Hamming</div>
              <div className="text-lg font-bold text-white mt-1">{threat.pHashDistance} bits</div>
            </div>
            <div className="p-3 rounded bg-[#121214] border border-[#27272a]">
              <div className="text-[#71717a] text-[10px] uppercase">OCR Logo Match</div>
              <div className="text-lg font-bold text-white mt-1">{threat.logoConfidence}%</div>
            </div>
            <div className="p-3 rounded bg-[#121214] border border-[#27272a]">
              <div className="text-[#71717a] text-[10px] uppercase">Syndicate</div>
              <div className="text-xs font-bold text-white mt-1 truncate">{threat.threatActorSyndicate}</div>
            </div>
          </div>

          {/* Network & Infrastructure */}
          <div className="p-4 rounded bg-[#121214] border border-[#27272a] space-y-3">
            <div className="font-bold text-xs text-white uppercase flex items-center space-x-2">
              <Server className="w-4 h-4 text-white" />
              <span>Hosting & Network Telemetry</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="space-y-1">
                <div><span className="text-[#71717a]">Registrar:</span> <span className="text-white">{threat.registrar}</span></div>
                <div><span className="text-[#71717a]">Host IP:</span> <span className="text-white">{threat.ip} ({threat.country})</span></div>
                <div><span className="text-[#71717a]">ASN:</span> <span className="text-white">{threat.asn} — {threat.asnName}</span></div>
              </div>
              <div className="space-y-1">
                <div><span className="text-[#71717a]">SSL Issuer:</span> <span className="text-white">{threat.sslIssuer}</span></div>
                <div><span className="text-[#71717a]">SSL Serial:</span> <span className="text-white">{threat.sslSerial}</span></div>
                <div><span className="text-[#71717a]">Nameservers:</span> <span className="text-white">{threat.dnsNameservers.join(', ')}</span></div>
              </div>
            </div>
          </div>

          {/* Harvested VPAs & Phones */}
          <div className="p-4 rounded bg-[#121214] border border-[#27272a] space-y-3">
            <div className="font-bold text-xs text-white uppercase flex items-center space-x-2">
              <Shield className="w-4 h-4 text-white" />
              <span>Harvested Fraud & Payment Vectors</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <div className="text-[#71717a] text-[10px] uppercase mb-1">Identified Malicious UPI VPAs:</div>
                <div className="space-y-1">
                  {threat.extractedUPI_VPA?.map(vpa => (
                    <div key={vpa} className="p-1.5 rounded bg-[#000000] border border-[#27272a] text-white">
                      {vpa}
                    </div>
                  )) || <div className="text-[#71717a]">None</div>}
                </div>
              </div>

              <div>
                <div className="text-[#71717a] text-[10px] uppercase mb-1">Associated Scam Phone Numbers:</div>
                <div className="space-y-1">
                  {threat.extractedPhoneNumbers?.map(ph => (
                    <div key={ph} className="p-1.5 rounded bg-[#000000] border border-[#27272a] text-white">
                      {ph}
                    </div>
                  )) || <div className="text-[#71717a]">None</div>}
                </div>
              </div>
            </div>
          </div>

          {/* Audit Timeline */}
          <div className="p-4 rounded bg-[#121214] border border-[#27272a] space-y-3">
            <div className="font-bold text-xs text-white uppercase flex items-center space-x-2">
              <Clock className="w-4 h-4 text-white" />
              <span>Incident Audit Log</span>
            </div>
            <div className="space-y-2 border-l border-[#27272a] ml-2 pl-4">
              {threat.timeline.map((event, idx) => (
                <div key={idx} className="relative text-xs">
                  <span className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-white" />
                  <div className="flex items-center space-x-2">
                    <span className="text-white font-bold">{event.time}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#000000] text-[#a1a1aa]">{event.actor}</span>
                  </div>
                  <div className="text-[#d4d4d8] mt-0.5">{event.event}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Action Bar */}
          <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-[#27272a]">
            <div className="text-[11px] text-[#71717a]">
              Digest: SHA256({threat.evidenceHash.slice(0, 16)}...)
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => {
                  onClose();
                  onOpenSimilarity(threat.id);
                }}
                className="px-3 py-1.5 rounded bg-[#121214] hover:bg-[#1f1f23] text-white border border-[#27272a] text-xs flex items-center space-x-1.5"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Visual Studio</span>
              </button>

              <button
                onClick={() => {
                  onClose();
                  onOpenTakedowns(threat.id);
                }}
                className="px-4 py-1.5 rounded bg-white text-black hover:bg-[#e4e4e7] font-semibold text-xs flex items-center space-x-1.5 shadow-sm"
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
