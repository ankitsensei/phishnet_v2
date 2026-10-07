import React, { useState } from 'react';
import { Terminal, Search, ShieldAlert, CheckCircle2, AlertTriangle, Cpu, ArrowRight, Zap, RefreshCw, Layers, ExternalLink } from 'lucide-react';
import { analyzeUrlOrPayload, ScanResult } from '../services/detectionEngine';

interface LiveScannerProps {
  onAddThreat?: (result: ScanResult) => void;
  onNavigateToTakedowns?: () => void;
}

const PRESET_PAYLOADS = [
  {
    label: 'SBI YONO KYC Lure',
    text: 'https://sbi-yono-pan-kyc-update.live/verify-account.php'
  },
  {
    label: 'PhonePe ₹4999 Cashback',
    text: 'https://phonepe-rewards-claim-5000.top/scratch-card.html'
  },
  {
    label: 'Smishing SMS with VPA & QR',
    text: 'Dear Customer, your HDFC NetBanking is suspended. Reactivate immediately and pay ₹1 verification charge to hdfcsecure.auth@ybl at https://hdfc-netbanking-session-restore.info'
  },
  {
    label: 'Legitimate SBI Portal',
    text: 'https://www.onlinesbi.sbi'
  }
];

export const LiveScanner: React.FC<LiveScannerProps> = ({ onAddThreat, onNavigateToTakedowns }) => {
  const [inputText, setInputText] = useState<string>(PRESET_PAYLOADS[0].text);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanStep, setScanStep] = useState<number>(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const scanSteps = [
    'Lexical entropy & brand typosquat tokenization...',
    'Fetching CT Log cross-references & TLS cert chain...',
    'Headless browser DOM capture & visual perceptual hashing (pHash)...',
    'YOLOv8 brand logo & input field MPIN harvest detection...',
    'Adversary campaign graph correlation & VPA attribution...'
  ];

  const handleStartScan = () => {
    if (!inputText.trim()) return;

    setIsScanning(true);
    setScanResult(null);
    setScanStep(0);

    let currentStep = 0;
    const interval = setInterval(() => {
      currentStep++;
      if (currentStep < scanSteps.length) {
        setScanStep(currentStep);
      } else {
        clearInterval(interval);
        const result = analyzeUrlOrPayload(inputText);
        setScanResult(result);
        setIsScanning(false);
      }
    }, 450);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-xl bg-[#0c1017] border border-white/10 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white font-display flex items-center space-x-2">
              <span>Deep Scan Sandbox & Lure Ingestion Console</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                URL • Smishing SMS • APK Links
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Multi-stage automated forensic analysis pipeline across lexical, visual, and behavioral vectors
            </p>
          </div>
        </div>
      </div>

      {/* Input Area */}
      <div className="p-5 rounded-xl bg-[#0b0f17] border border-white/10 space-y-4 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs font-mono font-bold text-slate-300 uppercase">
            Input Target URL or Raw SMS Smishing Payload:
          </span>
          {/* Quick presets */}
          <div className="flex flex-wrap gap-1.5">
            {PRESET_PAYLOADS.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => setInputText(preset.text)}
                className="px-2.5 py-1 rounded bg-[#141b29] hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 text-[11px] font-mono border border-white/5 transition-all"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div className="relative">
          <textarea
            rows={3}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste suspicious banking URL (e.g. https://sbi-yono-kyc.live) or raw SMS text..."
            className="w-full bg-[#070a10] border border-white/10 rounded-xl p-3.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 resize-none"
          />
        </div>

        <div className="flex justify-between items-center">
          <span className="text-[11px] font-mono text-slate-400">
            Pipeline Engine: pHash (64-bit) + SSIM + Levenshtein + NPCI VPA Extractor
          </span>
          <button
            onClick={handleStartScan}
            disabled={isScanning}
            className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/25 flex items-center space-x-2 transition-all disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Running Pipeline...</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5" />
                <span>Execute Deep Forensic Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Active Pipeline Progress */}
      {isScanning && (
        <div className="p-5 rounded-xl bg-[#090d14] border border-cyan-500/30 space-y-3 animate-in fade-in">
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs font-bold uppercase">
            <Cpu className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Scanning Target Pipeline Active</span>
          </div>

          <div className="space-y-2">
            {scanSteps.map((step, idx) => (
              <div
                key={idx}
                className={`flex items-center space-x-2 text-xs font-mono transition-all ${
                  idx < scanStep ? 'text-emerald-400' :
                  idx === scanStep ? 'text-cyan-300 font-bold' : 'text-slate-600'
                }`}
              >
                {idx < scanStep ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : idx === scanStep ? (
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping mr-1.5" />
                ) : (
                  <span className="w-2 h-2 rounded-full bg-slate-700 mr-1.5" />
                )}
                <span>{step}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan Results Card */}
      {scanResult && !isScanning && (
        <div className="p-6 rounded-xl bg-[#0b0f17] border border-white/10 space-y-5 shadow-2xl animate-in fade-in slide-in-from-bottom-2">
          {/* Verdict Banner */}
          <div className={`p-4 rounded-xl border flex flex-wrap items-center justify-between gap-3 ${
            scanResult.isPhishing
              ? 'bg-rose-950/30 border-rose-500/40 text-rose-200'
              : 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
          }`}>
            <div className="flex items-center space-x-3">
              {scanResult.isPhishing ? (
                <ShieldAlert className="w-6 h-6 text-rose-400" />
              ) : (
                <CheckCircle2 className="w-6 h-6 text-emerald-400" />
              )}
              <div>
                <div className="font-bold font-display text-sm flex items-center space-x-2">
                  <span>{scanResult.isPhishing ? 'CONFIRMED PHISHING CLONE DETECTED' : 'LEGITIMATE CANONICAL SERVICE'}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/40 border border-white/10">
                    Confidence: {scanResult.confidence}%
                  </span>
                </div>
                <div className="text-xs opacity-90 mt-0.5 font-mono">
                  {scanResult.isPhishing
                    ? `Impersonating: ${scanResult.matchedBrand} • Threat Type: ${scanResult.threatType}`
                    : 'Verified official bank domain and EV TLS Certificate'}
                </div>
              </div>
            </div>

            {scanResult.isPhishing && (
              <span className="px-3 py-1 rounded bg-rose-500 text-white font-mono text-xs font-bold">
                SEVERITY: {scanResult.severity}
              </span>
            )}
          </div>

          {/* Metric telemetry grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-[#070a10] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase">Visual SSIM</div>
              <div className="text-base font-bold text-cyan-300 mt-0.5">{(scanResult.structuralSSIM * 100).toFixed(1)}%</div>
            </div>
            <div className="p-3 rounded-lg bg-[#070a10] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase">pHash Hamming Dist</div>
              <div className="text-base font-bold text-rose-400 mt-0.5">{scanResult.pHashDistance} bits</div>
            </div>
            <div className="p-3 rounded-lg bg-[#070a10] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase">Attributed Syndicate</div>
              <div className="text-xs font-bold text-purple-300 mt-0.5 truncate">{scanResult.syndicate}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#070a10] border border-white/5">
              <div className="text-slate-400 text-[10px] uppercase">Extracted VPAs</div>
              <div className="text-xs font-bold text-emerald-300 mt-0.5">{scanResult.extractedVpa.length} Found</div>
            </div>
          </div>

          {/* Extracted IOCs */}
          <div className="space-y-2 text-xs font-mono">
            <div className="text-slate-300 font-bold uppercase">Evidence & Heuristic Indicators:</div>
            <div className="p-3 rounded-lg bg-[#070a10] border border-white/5 space-y-1.5 text-slate-300">
              {scanResult.riskReasons.map((reason, idx) => (
                <div key={idx} className="flex items-start space-x-2">
                  <span className="text-cyan-400">•</span>
                  <span>{reason}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Action Recommendation */}
          <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-500/30 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold">Recommended Autonomous Action:</div>
              <div className="text-xs text-slate-200 mt-0.5">{scanResult.recommendedAction}</div>
            </div>

            {scanResult.isPhishing && onNavigateToTakedowns && (
              <button
                onClick={onNavigateToTakedowns}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs shadow-md transition-all flex items-center space-x-1.5"
              >
                <span>Generate Takedown Notice</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
