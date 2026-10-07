import React, { useState } from 'react';
import { Eye, ShieldAlert, CheckCircle2, SplitSquareVertical, Cpu, AlertTriangle, Fingerprint, Lock, Layers, Code, Zap, ExternalLink } from 'lucide-react';
import { TargetBrand, ThreatItem } from '../types/threat';
import { GENUINE_BRAND_TEMPLATES } from '../data/mockThreats';

interface VisualSimilarityInspectorProps {
  threats: ThreatItem[];
  selectedThreatId?: string;
}

export const VisualSimilarityInspector: React.FC<VisualSimilarityInspectorProps> = ({
  threats,
  selectedThreatId
}) => {
  const [activeThreatId, setActiveThreatId] = useState<string>(selectedThreatId || threats[0]?.id || 'thr-8901');
  const [comparisonMode, setComparisonMode] = useState<'SIDE_BY_SIDE' | 'OVERLAY_HEATMAP' | 'DOM_DIFF'>('SIDE_BY_SIDE');
  const [sliderPosition, setSliderPosition] = useState<number>(50);

  const threat = threats.find(t => t.id === activeThreatId) || threats[0];
  const genuineBrand = GENUINE_BRAND_TEMPLATES[threat.targetBrand] || GENUINE_BRAND_TEMPLATES['SBI YONO'];

  return (
    <div className="space-y-6">
      {/* Top Banner & Threat Selector */}
      <div className="p-4 rounded-xl bg-[#0c1017] border border-white/10 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Eye className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white font-display flex items-center space-x-2">
              <span>Visual & Behavioral Clone Matching Engine</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                pHash • SSIM • DOM Tree
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Perceptual image hashing, structural layout alignment & credential harvest intent detection
            </p>
          </div>
        </div>

        {/* Threat Switcher */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Sample Phish:</span>
          <select
            value={activeThreatId}
            onChange={(e) => setActiveThreatId(e.target.value)}
            className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {threats.map(t => (
              <option key={t.id} value={t.id}>
                [{t.targetBrand}] {t.domain} (SSIM: {(t.structuralSSIM * 100).toFixed(1)}%)
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Similarity Score Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0d121c] border border-cyan-500/20 relative overflow-hidden">
          <div className="text-[11px] uppercase font-mono text-slate-400 flex items-center justify-between">
            <span>Perceptual SSIM</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-cyan-300">
            {(threat.structuralSSIM * 100).toFixed(1)}%
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            Structural Similarity Index against official template
          </div>
          <div className="w-full bg-white/5 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-cyan-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${threat.structuralSSIM * 100}%` }}
            />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d121c] border border-rose-500/20 relative overflow-hidden">
          <div className="text-[11px] uppercase font-mono text-slate-400 flex items-center justify-between">
            <span>pHash Hamming Distance</span>
            <Fingerprint className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-rose-400">
            {threat.pHashDistance} <span className="text-xs font-normal text-slate-400">/ 64 bits</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            {threat.pHashDistance <= 5 ? 'Exact visual clone detected' : 'Near-duplicate layout'}
          </div>
          <div className="w-full bg-white/5 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-rose-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.max(10, (1 - threat.pHashDistance / 64) * 100)}%` }}
            />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d121c] border border-amber-500/20 relative overflow-hidden">
          <div className="text-[11px] uppercase font-mono text-slate-400 flex items-center justify-between">
            <span>Logo Match Confidence</span>
            <Eye className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-300">
            {threat.logoConfidence}%
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            YOLOv8 + OCR detected genuine brand mark
          </div>
          <div className="w-full bg-white/5 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-amber-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${threat.logoConfidence}%` }}
            />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d121c] border border-purple-500/20 relative overflow-hidden">
          <div className="text-[11px] uppercase font-mono text-slate-400 flex items-center justify-between">
            <span>DOM Tree Edit Ratio</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-purple-300">
            {(threat.domEditDistance * 100).toFixed(1)}% <span className="text-xs font-normal text-slate-400">delta</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            96% node-by-node DOM tag alignment
          </div>
          <div className="w-full bg-white/5 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-purple-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${(1 - threat.domEditDistance) * 100}%` }}
            />
          </div>
        </div>
      </div>

      {/* Main Visual Comparison Viewport */}
      <div className="p-5 rounded-xl bg-[#0b0f17] border border-white/10 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div className="flex items-center space-x-3">
            <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              Visual Alignment Studio
            </span>
            <span className="text-xs text-slate-400">
              Impersonated Brand: <strong className="text-white">{threat.targetBrand}</strong>
            </span>
          </div>

          <div className="flex items-center space-x-2 bg-[#121824] p-1 rounded-lg border border-white/10 text-xs">
            <button
              onClick={() => setComparisonMode('SIDE_BY_SIDE')}
              className={`px-2.5 py-1 rounded font-medium transition-all ${
                comparisonMode === 'SIDE_BY_SIDE'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Side-by-Side Diff
            </button>
            <button
              onClick={() => setComparisonMode('OVERLAY_HEATMAP')}
              className={`px-2.5 py-1 rounded font-medium transition-all ${
                comparisonMode === 'OVERLAY_HEATMAP'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Interactive Slider
            </button>
            <button
              onClick={() => setComparisonMode('DOM_DIFF')}
              className={`px-2.5 py-1 rounded font-medium transition-all ${
                comparisonMode === 'DOM_DIFF'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              DOM Intent Nodes
            </button>
          </div>
        </div>

        {/* Mode 1: Side by side */}
        {comparisonMode === 'SIDE_BY_SIDE' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Suspicious Phish Mockup */}
            <div className="rounded-xl bg-[#0e1420] border border-rose-500/30 overflow-hidden shadow-lg">
              <div className="px-4 py-2.5 bg-rose-950/40 border-b border-rose-500/20 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
                  <span className="text-xs font-mono font-bold text-rose-300 uppercase">
                    Detected Malicious Clone
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-400 truncate max-w-[200px]">
                  {threat.domain}
                </span>
              </div>

              {/* Rendered simulated UI clone */}
              <div className="p-6 bg-gradient-to-b from-[#141b2b] to-[#0c1018] min-h-[380px] flex flex-col justify-between relative">
                {/* Fake badge watermark */}
                <div className="absolute top-3 right-3 px-2 py-1 rounded bg-rose-500/20 border border-rose-500/40 text-[10px] font-mono text-rose-300">
                  CLONE CONFIDENCE: {threat.similarityScore}%
                </div>

                <div className="space-y-4">
                  {/* Brand Header */}
                  <div className="flex items-center space-x-3 border-b border-white/10 pb-3">
                    <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-purple-600 to-blue-600 flex items-center justify-center font-bold text-white text-sm shadow-md">
                      {threat.targetBrand.slice(0, 2)}
                    </div>
                    <div>
                      <div className="font-bold text-sm text-white">{threat.targetBrand} Official Portal</div>
                      <div className="text-[10px] text-slate-400 font-mono">KYC / Reward Verification Desk</div>
                    </div>
                  </div>

                  {/* Lure Message */}
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200">
                    <p className="font-semibold">⚠️ Urgent Action Required</p>
                    <p className="text-[11px] text-slate-300 mt-1">
                      Your account verification is pending. Enter your UPI PIN / MPIN to release your pending cashback and prevent suspension.
                    </p>
                  </div>

                  {/* Harvested Inputs */}
                  <div className="space-y-2.5">
                    <div>
                      <label className="text-[11px] text-slate-300 block mb-1">Registered Mobile Number</label>
                      <input
                        type="text"
                        disabled
                        value="+91 98765 XXXXX"
                        className="w-full bg-[#080b11] border border-white/10 rounded px-3 py-1.5 text-xs text-slate-400 font-mono"
                      />
                    </div>
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <label className="text-[11px] text-rose-400 font-semibold flex items-center space-x-1">
                          <Lock className="w-3 h-3 text-rose-400" />
                          <span>6-Digit UPI PIN / MPIN (Fraud Vector)</span>
                        </label>
                        <span className="text-[9px] font-mono text-rose-400 px-1 rounded bg-rose-500/20">HARVESTED</span>
                      </div>
                      <input
                        type="password"
                        disabled
                        value="••••••"
                        className="w-full bg-rose-950/30 border border-rose-500/50 rounded px-3 py-1.5 text-xs text-rose-300 font-mono tracking-widest"
                      />
                    </div>
                  </div>
                </div>

                {/* Footer fake CTA */}
                <div className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between">
                  <span className="text-[10px] text-slate-400 font-mono">Form Action: /steal_creds.php</span>
                  <button className="px-3 py-1.5 rounded bg-rose-600/80 text-white font-semibold text-xs shadow-lg shadow-rose-600/30">
                    Submit & Verify
                  </button>
                </div>
              </div>
            </div>

            {/* Genuine Reference */}
            <div className="rounded-xl bg-[#0e1420] border border-emerald-500/30 overflow-hidden shadow-lg">
              <div className="px-4 py-2.5 bg-emerald-950/40 border-b border-emerald-500/20 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-mono font-bold text-emerald-300 uppercase">
                    Genuine Verified Template
                  </span>
                </div>
                <a
                  href={threat.genuineReferenceUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center space-x-1"
                >
                  <span>{genuineBrand.officialDomain}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Genuine Portal Representation */}
              <div className="p-6 bg-gradient-to-b from-[#101b24] to-[#0c1218] min-h-[380px] flex flex-col justify-between">
                <div className="space-y-4">
                  {/* Brand Header */}
                  <div className="flex items-center space-x-3 border-b border-white/10 pb-3">
                    <div
                      className="w-9 h-9 rounded-lg flex items-center justify-center font-bold text-white text-sm shadow-md"
                      style={{ backgroundColor: genuineBrand.colorTheme || '#06b6d4' }}
                    >
                      {threat.targetBrand.slice(0, 2)}
                    </div>
                    <div>
                      <div className="font-bold text-sm text-white">{genuineBrand.name}</div>
                      <div className="text-[10px] text-emerald-400 font-mono">TLS 1.3 Validated EV Certificate</div>
                    </div>
                  </div>

                  {/* Security Policy Alert */}
                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-200">
                    <p className="font-semibold flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Zero-Trust UPI Advisory</span>
                    </p>
                    <p className="text-[11px] text-slate-300 mt-1">
                      {genuineBrand.securityNotice}
                    </p>
                  </div>

                  {/* Official Guidelines */}
                  <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-2 text-xs">
                    <div className="text-[11px] text-slate-400 font-mono uppercase">Official UPI VPA Suffixes:</div>
                    <div className="flex flex-wrap gap-1.5">
                      {genuineBrand.officialVpaHandleSuffixes.map(s => (
                        <span key={s} className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px] border border-emerald-500/30">
                          {s}
                        </span>
                      ))}
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono uppercase mt-2">Common Attack Vectors:</div>
                    <div className="flex flex-wrap gap-1.5">
                      {genuineBrand.commonLureVectors.map(v => (
                        <span key={v} className="px-2 py-0.5 rounded bg-white/5 text-slate-300 text-[10px]">
                          {v}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-xs text-slate-400">
                  <span>Canonical DOM Checksum: 0x9fa1...b420</span>
                  <span className="text-emerald-400 font-mono">EV SSL: Digicert Root</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Mode 2: Interactive Slider Overlay */}
        {comparisonMode === 'OVERLAY_HEATMAP' && (
          <div className="space-y-4">
            <div className="relative rounded-xl overflow-hidden border border-cyan-500/30 bg-[#0d121c] h-[360px]">
              {/* Fake Background Layer */}
              <div className="absolute inset-0 p-8 flex flex-col justify-center items-center bg-gradient-to-br from-rose-950/50 to-slate-950 text-center">
                <div className="text-rose-400 font-mono text-sm font-bold">SUSPICIOUS CLONE VIEWPORT</div>
                <div className="text-xs text-slate-400 mt-1">{threat.domain}</div>
                <div className="mt-6 p-4 rounded-lg bg-rose-500/20 border border-rose-500/40 text-xs text-rose-200 max-w-md">
                  Fake UPI PIN harvest modal overlaid directly on {threat.targetBrand} branded layout.
                </div>
              </div>

              {/* Genuine Layer with clip-path based on slider */}
              <div
                className="absolute inset-0 p-8 flex flex-col justify-center items-center bg-gradient-to-br from-emerald-950/50 to-slate-950 text-center transition-all"
                style={{ clipPath: `inset(0 0 0 ${sliderPosition}%)` }}
              >
                <div className="text-emerald-400 font-mono text-sm font-bold">GENUINE CANONICAL TEMPLATE</div>
                <div className="text-xs text-slate-400 mt-1">{genuineBrand.officialDomain}</div>
                <div className="mt-6 p-4 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-xs text-emerald-200 max-w-md">
                  Official authentic portal structure with valid CSP, EV-SSL and no credential forms.
                </div>
              </div>

              {/* Vertical Divider Bar */}
              <div
                className="absolute top-0 bottom-0 w-1 bg-cyan-400 shadow-[0_0_12px_#06b6d4] pointer-events-none"
                style={{ left: `${sliderPosition}%` }}
              />
            </div>

            {/* Slider control */}
            <div className="flex items-center space-x-4 px-2">
              <span className="text-xs font-mono text-rose-400">Clone (100%)</span>
              <input
                type="range"
                min="0"
                max="100"
                value={sliderPosition}
                onChange={(e) => setSliderPosition(Number(e.target.value))}
                className="flex-1 accent-cyan-400 h-2 bg-slate-800 rounded-lg cursor-pointer"
              />
              <span className="text-xs font-mono text-emerald-400">Genuine (100%)</span>
            </div>
          </div>
        )}

        {/* Mode 3: DOM Diff & Intent extraction */}
        {comparisonMode === 'DOM_DIFF' && (
          <div className="p-4 rounded-xl bg-[#090d14] border border-white/10 space-y-3 font-mono text-xs">
            <div className="text-cyan-400 font-bold text-xs uppercase flex items-center space-x-2">
              <Code className="w-4 h-4 text-cyan-400" />
              <span>Extracted Malicious DOM Payload & Hooks</span>
            </div>
            <div className="bg-[#05080d] p-3 rounded-lg border border-white/5 space-y-1 text-slate-300 overflow-x-auto text-[11px]">
              <div className="text-slate-500">// Intercepted HTML Form Target & Malicious JavaScript Handlers</div>
              <div className="text-rose-400">&lt;form action="https://{threat.domain}/api/v1/harvest.php" method="POST"&gt;</div>
              <div className="pl-4 text-slate-300">&lt;input type="hidden" name="vpa_target" value="{threat.extractedUPI_VPA?.[0] || 'sbikyc.refund99@paytm'}" /&gt;</div>
              <div className="pl-4 text-rose-300">&lt;input type="password" name="user_mpin" maxlength="6" data-intercept="true" /&gt;</div>
              <div className="pl-4 text-slate-300">&lt;input type="text" name="pan_card" placeholder="ABCDE1234F" /&gt;</div>
              <div className="text-rose-400">&lt;/form&gt;</div>
              <div className="text-slate-500 mt-2">// Disguised UPI Intent Scheme</div>
              <div className="text-cyan-300">window.location.href = "{threat.qrCodePayload || `upi://pay?pa=${threat.extractedUPI_VPA?.[0]}&pn=Verification&am=1.00`}";</div>
            </div>
          </div>
        )}

        {/* Evasion Tactics Detected Bar */}
        <div className="p-4 rounded-xl bg-[#0d121c] border border-white/10">
          <div className="text-xs font-mono font-bold text-white uppercase mb-3 flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>Adversary Evasion & Anti-Analysis Tactics Active</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
            {Object.entries(threat.evasionTactics).map(([tactic, active]) => (
              <div
                key={tactic}
                className={`p-2 rounded-lg border text-xs flex items-center justify-between font-mono ${
                  active
                    ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                    : 'bg-white/5 border-white/5 text-slate-500'
                }`}
              >
                <span className="truncate text-[11px]">
                  {tactic.replace(/([A-Z])/g, ' $1').trim()}
                </span>
                <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                  active ? 'bg-rose-500/20 text-rose-300' : 'bg-white/10 text-slate-500'
                }`}>
                  {active ? 'DETECTED' : 'CLEAR'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
