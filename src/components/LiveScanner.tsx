import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle, ArrowRight, Upload, Sparkles, FileText, AlertTriangle, ExternalLink } from 'lucide-react';
import { analyzeSource, ScanResult } from '../services/detectionEngine';

interface LiveScannerProps {
  onAddThreat?: (result: ScanResult) => void;
  onNavigateToTakedowns?: () => void;
}

const QUICK_SAMPLES = [
  {
    label: 'Fake SBI KYC Link',
    value: 'https://sbi-yono-pan-kyc-update.live/verify-account.php'
  },
  {
    label: 'PhonePe ₹4,999 SMS Scam',
    value: 'Dear User, congrats! ₹4,999 cashback credited in your PhonePe wallet. Claim now by entering your 6-Digit UPI PIN at https://phonepe-rewards-claim-5000.top/scratch-card.html or pay ₹1 to phonepe.reward.claim@axl'
  },
  {
    label: 'Fake Paytm Web Form (HTML)',
    value: `<form action="https://paytm-kyc-unblock.top/steal.php" method="POST">\n  <h2>Paytm Instant Wallet KYC</h2>\n  <input type="text" name="mobile" placeholder="Mobile Number" />\n  <input type="password" name="mpin" placeholder="Enter 6-digit UPI PIN" />\n  <button type="submit">Verify Now</button>\n</form>`
  },
  {
    label: 'Fake SBI YONO APK (Manifest)',
    value: `<manifest package="com.sbi.lotusapply.banking">\n  <uses-permission android:name="android.permission.RECEIVE_SMS" />\n  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />\n  <intent-filter><action android:name="android.intent.action.VIEW" /><data android:scheme="upi" android:host="pay" /></intent-filter>\n</manifest>`
  },
  {
    label: 'Genuine Bank (onlinesbi.sbi)',
    value: 'https://www.onlinesbi.sbi'
  }
];

export const LiveScanner: React.FC<LiveScannerProps> = ({ onAddThreat, onNavigateToTakedowns }) => {
  const [inputText, setInputText] = useState<string>(QUICK_SAMPLES[0].value);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [result, setResult] = useState<ScanResult | null>(() => analyzeSource(QUICK_SAMPLES[0].value));

  const handleScan = () => {
    if (!inputText.trim()) return;
    setIsScanning(true);

    setTimeout(() => {
      const res = analyzeSource(inputText);
      setResult(res);
      setIsScanning(false);
      if (onAddThreat && res.isFake) {
        onAddThreat(res);
      }
    }, 250);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setInputText(content || file.name);
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Title & Intro */}
      <div className="text-center space-y-1.5 pt-2">
        <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
          Fake UPI & Payment Page / App Detector
        </h1>
        <p className="text-xs text-[#888892] max-w-lg mx-auto">
          Paste any website link, HTML page code, SMS message, UPI ID, or APK details to detect the fake percentage instantly.
        </p>
      </div>

      {/* Main Input Box */}
      <div className="p-4 sm:p-5 rounded-xl bg-[#09090b] border border-[#222226] space-y-3.5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label className="text-xs font-semibold text-white">
            Paste Source to Check:
          </label>
          <label className="cursor-pointer text-[11px] text-[#888892] hover:text-white flex items-center space-x-1 font-mono transition-colors">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload File (.html / .apk / .txt)</span>
            <input type="file" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>

        <div className="relative">
          <textarea
            rows={4}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste URL (e.g. https://sbi-yono-kyc.live), HTML source code, SMS text, or UPI handle..."
            className="w-full bg-[#000000] border border-[#222226] rounded-lg p-3 text-xs text-white font-mono focus:outline-none focus:border-white focus:ring-1 focus:ring-white transition-all resize-none leading-relaxed"
          />
        </div>

        {/* Quick Sample Chips & Check Button */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-[#55555c] font-mono mr-1">Quick Samples:</span>
            {QUICK_SAMPLES.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setInputText(sample.value);
                  setTimeout(() => {
                    const res = analyzeSource(sample.value);
                    setResult(res);
                  }, 50);
                }}
                className="px-2.5 py-1 rounded bg-[#121214] hover:bg-[#1a1a1e] text-[#a1a1aa] hover:text-white text-[11px] font-mono border border-[#222226] transition-colors"
              >
                {sample.label}
              </button>
            ))}
          </div>

          <button
            onClick={handleScan}
            disabled={isScanning}
            className="px-5 py-2 rounded-lg bg-white text-black hover:bg-[#e4e4e7] text-xs font-semibold shadow-sm flex items-center space-x-2 transition-all disabled:opacity-50"
          >
            {isScanning ? (
              <span>Analyzing...</span>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                <span>Detect Fake Percentage</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-4 animate-in fade-in duration-150">
          {/* Main Verdict Banner */}
          <div className={`p-5 rounded-xl border flex flex-wrap items-center justify-between gap-4 ${
            result.isFake
              ? 'bg-[#0e0e10] border-white'
              : 'bg-[#09090b] border-[#222226]'
          }`}>
            <div className="flex items-center space-x-4">
              {/* Fake Percentage Circle */}
              <div className="w-14 h-14 rounded-full bg-white text-black flex flex-col items-center justify-center font-mono font-bold leading-none shadow-md">
                <span className="text-base font-extrabold">{result.overallFakePercentage}%</span>
                <span className="text-[9px] uppercase tracking-wider">{result.isFake ? 'FAKE' : 'SAFE'}</span>
              </div>

              <div>
                <div className="text-base font-bold text-white tracking-tight flex items-center space-x-2">
                  <span>{result.isFake ? 'Fake Cloned Interface Detected' : 'Verified Genuine Service'}</span>
                </div>
                <div className="text-xs text-[#a1a1aa] mt-0.5 font-mono">
                  {result.isFake ? (
                    <>
                      Impersonating <strong className="text-white">{result.matchedBrand}</strong> • Official Genuine Site is <span className="text-white underline">{result.genuineBrandDomain}</span>
                    </>
                  ) : (
                    'Matches official authentic banking registry'
                  )}
                </div>
              </div>
            </div>

            {result.isFake && onNavigateToTakedowns && (
              <button
                onClick={onNavigateToTakedowns}
                className="px-4 py-2 rounded-lg bg-white text-black hover:bg-[#e4e4e7] text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-sm"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>1-Click Takedown Report</span>
              </button>
            )}
          </div>

          {/* 4 Factor Breakdown Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono">
            <div className="p-3.5 rounded-lg bg-[#09090b] border border-[#222226] space-y-1.5">
              <div className="text-[10px] uppercase text-[#71717a]">Visual Copy Match</div>
              <div className="text-xl font-bold text-white">{result.breakdown.visualCloneScore}%</div>
              <div className="w-full bg-[#1c1c20] h-1 rounded-full overflow-hidden">
                <div className="bg-white h-full" style={{ width: `${result.breakdown.visualCloneScore}%` }} />
              </div>
              <div className="text-[10px] text-[#71717a]">Brand design replica</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#09090b] border border-[#222226] space-y-1.5">
              <div className="text-[10px] uppercase text-[#71717a]">PIN / Password Theft</div>
              <div className="text-xl font-bold text-white">{result.breakdown.domHarvestScore}%</div>
              <div className="w-full bg-[#1c1c20] h-1 rounded-full overflow-hidden">
                <div className="bg-white h-full" style={{ width: `${result.breakdown.domHarvestScore}%` }} />
              </div>
              <div className="text-[10px] text-[#71717a]">Credential grab fields</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#09090b] border border-[#222226] space-y-1.5">
              <div className="text-[10px] uppercase text-[#71717a]">Fake Domain Risk</div>
              <div className="text-xl font-bold text-white">{result.breakdown.infrastructureScore}%</div>
              <div className="w-full bg-[#1c1c20] h-1 rounded-full overflow-hidden">
                <div className="bg-white h-full" style={{ width: `${result.breakdown.infrastructureScore}%` }} />
              </div>
              <div className="text-[10px] text-[#71717a]">Untrusted typosquat</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#09090b] border border-[#222226] space-y-1.5">
              <div className="text-[10px] uppercase text-[#71717a]">UPI Fraud Deception</div>
              <div className="text-xl font-bold text-white">{result.breakdown.upiFraudIntentScore}%</div>
              <div className="w-full bg-[#1c1c20] h-1 rounded-full overflow-hidden">
                <div className="bg-white h-full" style={{ width: `${result.breakdown.upiFraudIntentScore}%` }} />
              </div>
              <div className="text-[10px] text-[#71717a]">Collect request trap</div>
            </div>
          </div>

          {/* Details & Extracted VPAs */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
            {/* Why it is fake */}
            <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226] space-y-2">
              <div className="text-white font-bold text-[11px] uppercase">Detection Reasons:</div>
              <ul className="space-y-1 text-[#a1a1aa] text-[11px]">
                {result.riskReasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start space-x-1.5">
                    <span className="text-white font-bold">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Extracted Fraud VPAs */}
            <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226] space-y-2">
              <div className="text-white font-bold text-[11px] uppercase">Identified Fraud Payment Handles (VPAs):</div>
              {result.extractedVpa.length > 0 ? (
                <div className="space-y-1.5">
                  {result.extractedVpa.map((vpa) => (
                    <div key={vpa} className="p-2 rounded bg-[#000000] border border-[#222226] text-white flex items-center justify-between text-[11px]">
                      <span>{vpa}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#18181b] text-[#a1a1aa] border border-[#27272a]">
                        FLAGGED VPA
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[#55555c] text-[11px]">No active UPI handles found</div>
              )}

              {result.isFake && (
                <div className="pt-2 text-[10px] text-[#71717a]">
                  Syndicate Attribution: <strong className="text-white">{result.syndicate}</strong>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
