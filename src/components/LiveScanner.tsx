import React, { useState } from 'react';
import { Shield, AlertCircle, CheckCircle, Search, ArrowRight, Code, Smartphone, MessageSquare, Globe, CreditCard, RefreshCw, Upload, FileText } from 'lucide-react';
import { analyzeSource, SourceInputType, ScanResult } from '../services/detectionEngine';

interface LiveScannerProps {
  onAddThreat?: (result: ScanResult) => void;
  onNavigateToTakedowns?: () => void;
}

const PRESET_SOURCES = [
  {
    type: 'URL' as SourceInputType,
    label: 'Clone URL: SBI YONO KYC Lure',
    content: 'https://sbi-yono-pan-kyc-update.live/verify-account.php'
  },
  {
    type: 'HTML_SOURCE' as SourceInputType,
    label: 'Page Source: PhonePe ₹4,999 Fake Scratch Form',
    content: `<!DOCTYPE html>
<html>
<head><title>PhonePe Reward Verification Desk</title></head>
<body>
  <div class="header"><img src="/logo-phonepe.png" /> <h1>PhonePe Cashback Verification</h1></div>
  <p>Your ₹4,999 cashback is on hold. Enter your 6-Digit UPI PIN to confirm identity.</p>
  <form action="https://phonepe-rewards-claim-5000.top/api/harvest.php" method="POST">
    <input type="text" name="mobile" placeholder="Mobile Number" />
    <input type="password" name="upi_mpin" maxlength="6" placeholder="Enter 6-Digit UPI PIN" />
    <input type="hidden" name="vpa_receiver" value="phonepe.reward.claim@axl" />
    <button type="submit">Claim Cashback Immediately</button>
  </form>
</body>
</html>`
  },
  {
    type: 'SMS_TEXT' as SourceInputType,
    label: 'Smishing SMS: Electricity Bill & YONO Block',
    content: 'Dear Customer, your SBI YONO account will be blocked today due to pending PAN KYC. Update immediately at https://sbi-yono-pan-kyc-update.live or pay ₹1 verification charge to sbikyc.refund99@paytm to avoid UPI suspension.'
  },
  {
    type: 'APK_APP' as SourceInputType,
    label: 'APK App: SBI_Yono_Update_v4.2.apk (Manifest)',
    content: `<manifest package="com.sbi.lotusapply.banking">
  <uses-permission android:name="android.permission.RECEIVE_SMS" />
  <uses-permission android:name="android.permission.READ_SMS" />
  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="upi" android:host="pay" />
  </intent-filter>
  <!-- Hardcoded C2: https://api.shadowvpa-c2.top/collect.php -->
</manifest>`
  },
  {
    type: 'URL' as SourceInputType,
    label: 'Genuine Bank: Official onlinesbi.sbi',
    content: 'https://www.onlinesbi.sbi'
  }
];

export const LiveScanner: React.FC<LiveScannerProps> = ({ onAddThreat, onNavigateToTakedowns }) => {
  const [selectedType, setSelectedType] = useState<SourceInputType>('URL');
  const [inputContent, setInputContent] = useState<string>(PRESET_SOURCES[0].content);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const handleRunScan = () => {
    if (!inputContent.trim()) return;
    setIsAnalyzing(true);
    setScanResult(null);

    setTimeout(() => {
      const res = analyzeSource(inputContent, selectedType);
      setScanResult(res);
      setIsAnalyzing(false);
      if (onAddThreat && res.isFake) {
        onAddThreat(res);
      }
    }, 400);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setInputContent(content || file.name);
      if (file.name.endsWith('.apk')) {
        setSelectedType('APK_APP');
      } else if (file.name.endsWith('.html') || file.name.endsWith('.htm') || file.name.endsWith('.php')) {
        setSelectedType('HTML_SOURCE');
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight flex items-center space-x-2">
            <span>Fake UPI & Payment Page / App Detection Engine</span>
          </h2>
          <p className="text-xs text-[#a1a1aa] mt-0.5">
            Provide the source (URL, HTML source code, Smishing SMS, or APK package) to detect fake probability percentage-wise.
          </p>
        </div>

        {/* Source Type Selector */}
        <div className="flex items-center space-x-1 bg-[#121214] p-1 rounded-md border border-[#27272a] text-xs">
          {[
            { id: 'URL', label: 'URL / Link', icon: Globe },
            { id: 'HTML_SOURCE', label: 'Page HTML Source', icon: Code },
            { id: 'SMS_TEXT', label: 'Smishing SMS', icon: MessageSquare },
            { id: 'APK_APP', label: 'APK / App Manifest', icon: Smartphone },
            { id: 'UPI_VPA', label: 'UPI VPA / QR', icon: CreditCard },
          ].map((item) => {
            const Icon = item.icon;
            const isSelected = selectedType === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setSelectedType(item.id as SourceInputType)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  isSelected
                    ? 'bg-[#27272a] text-white border border-[#3f3f46]'
                    : 'text-[#a1a1aa] hover:text-white'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Input Area */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label className="text-xs font-mono font-medium text-white uppercase tracking-wider">
            Source Input ({selectedType}):
          </label>

          {/* Preset Buttons */}
          <div className="flex flex-wrap gap-1.5">
            {PRESET_SOURCES.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setSelectedType(preset.type);
                  setInputContent(preset.content);
                }}
                className="px-2.5 py-1 rounded bg-[#121214] hover:bg-[#1f1f23] text-[#a1a1aa] hover:text-white text-[11px] font-mono border border-[#27272a] transition-colors"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        {/* Text area */}
        <textarea
          rows={selectedType === 'HTML_SOURCE' || selectedType === 'APK_APP' ? 7 : 3}
          value={inputContent}
          onChange={(e) => setInputContent(e.target.value)}
          placeholder={
            selectedType === 'URL'
              ? 'Enter suspicious URL (e.g. https://sbi-yono-pan-kyc-update.live/login.php)...'
              : selectedType === 'HTML_SOURCE'
              ? 'Paste the cloned webpage HTML / DOM source code...'
              : selectedType === 'SMS_TEXT'
              ? 'Paste raw SMS message text (e.g. Dear user, your PhonePe cashback is credited...)...'
              : selectedType === 'APK_APP'
              ? 'Paste APK package name, AndroidManifest.xml, or decompiled strings...'
              : 'Enter UPI VPA handle (e.g. sbikyc.refund99@paytm) or upi://pay URI...'
          }
          className="w-full bg-[#000000] border border-[#27272a] rounded-lg p-3 text-xs text-[#f4f4f5] font-mono focus:outline-none focus:border-white focus:ring-1 focus:ring-white resize-none"
        />

        {/* Action Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex items-center space-x-2">
            <label className="cursor-pointer px-3 py-1.5 rounded bg-[#121214] hover:bg-[#1f1f23] border border-[#27272a] text-xs font-mono text-[#a1a1aa] hover:text-white flex items-center space-x-1.5 transition-colors">
              <Upload className="w-3.5 h-3.5" />
              <span>Upload File (.html / .apk / .txt)</span>
              <input type="file" onChange={handleFileUpload} className="hidden" />
            </label>
            <span className="text-[11px] text-[#71717a] font-mono">
              Auto-tokenized via pHash, SSIM, and DOM Credential Matcher
            </span>
          </div>

          <button
            onClick={handleRunScan}
            disabled={isAnalyzing}
            className="px-5 py-2 rounded-lg bg-white text-black hover:bg-[#e4e4e7] text-xs font-semibold shadow-sm flex items-center space-x-2 transition-colors disabled:opacity-50"
          >
            {isAnalyzing ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Analyzing Source...</span>
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                <span>Detect Fake Percentage</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scan Results: Percentage-Wise Breakdown */}
      {scanResult && !isAnalyzing && (
        <div className="p-6 rounded-lg bg-[#09090b] border border-[#27272a] space-y-6 animate-in fade-in duration-150">
          {/* Main Verdict Card */}
          <div className={`p-5 rounded-lg border flex flex-wrap items-center justify-between gap-4 ${
            scanResult.isFake
              ? 'bg-[#121214] border-white'
              : 'bg-[#09090b] border-[#27272a]'
          }`}>
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 rounded-lg bg-white text-black flex items-center justify-center font-mono font-bold text-lg">
                {scanResult.overallFakePercentage}%
              </div>
              <div>
                <div className="text-base font-bold text-white tracking-tight flex items-center space-x-2">
                  <span>{scanResult.isFake ? 'FAKE / CLONE DETECTED' : 'GENUINE / AUTHENTIC'}</span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#27272a] text-white border border-[#3f3f46]">
                    Severity: {scanResult.severity}
                  </span>
                </div>
                <div className="text-xs text-[#a1a1aa] font-mono mt-0.5">
                  Target Brand: <strong className="text-white">{scanResult.matchedBrand}</strong> • Official Domain: <span className="text-[#d4d4d8] underline">{scanResult.genuineBrandDomain}</span>
                </div>
              </div>
            </div>

            {scanResult.isFake && onNavigateToTakedowns && (
              <button
                onClick={onNavigateToTakedowns}
                className="px-4 py-2 rounded bg-white text-black hover:bg-[#e4e4e7] text-xs font-semibold flex items-center space-x-1.5 transition-colors"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Generate Takedown Notice</span>
              </button>
            )}
          </div>

          {/* Percentage-wise Detailed Factor Breakdown */}
          <div className="space-y-3">
            <div className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              Percentage-Wise Detection Breakdown:
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
              {/* Factor 1 */}
              <div className="p-3.5 rounded-lg bg-[#121214] border border-[#27272a] space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-[#a1a1aa]">Visual Clone Match</span>
                  <span className="text-white font-bold text-sm">{scanResult.breakdown.visualCloneScore}%</span>
                </div>
                <div className="w-full bg-[#27272a] h-1.5 rounded-full overflow-hidden">
                  <div className="bg-white h-full rounded-full" style={{ width: `${scanResult.breakdown.visualCloneScore}%` }} />
                </div>
                <div className="text-[10px] text-[#71717a]">SSIM pixel alignment & brand UI replication</div>
              </div>

              {/* Factor 2 */}
              <div className="p-3.5 rounded-lg bg-[#121214] border border-[#27272a] space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-[#a1a1aa]">DOM & PIN Harvest Risk</span>
                  <span className="text-white font-bold text-sm">{scanResult.breakdown.domHarvestScore}%</span>
                </div>
                <div className="w-full bg-[#27272a] h-1.5 rounded-full overflow-hidden">
                  <div className="bg-white h-full rounded-full" style={{ width: `${scanResult.breakdown.domHarvestScore}%` }} />
                </div>
                <div className="text-[10px] text-[#71717a]">Fake MPIN, Password & CVV steal hooks</div>
              </div>

              {/* Factor 3 */}
              <div className="p-3.5 rounded-lg bg-[#121214] border border-[#27272a] space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-[#a1a1aa]">Infrastructure Malice</span>
                  <span className="text-white font-bold text-sm">{scanResult.breakdown.infrastructureScore}%</span>
                </div>
                <div className="w-full bg-[#27272a] h-1.5 rounded-full overflow-hidden">
                  <div className="bg-white h-full rounded-full" style={{ width: `${scanResult.breakdown.infrastructureScore}%` }} />
                </div>
                <div className="text-[10px] text-[#71717a]">Typosquat entropy, TLD risk & bulletproof IP</div>
              </div>

              {/* Factor 4 */}
              <div className="p-3.5 rounded-lg bg-[#121214] border border-[#27272a] space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-[#a1a1aa]">UPI Collect Deception</span>
                  <span className="text-white font-bold text-sm">
                    {scanResult.breakdown.appMaliceScore !== undefined
                      ? `${scanResult.breakdown.appMaliceScore}%`
                      : `${scanResult.breakdown.upiFraudIntentScore}%`}
                  </span>
                </div>
                <div className="w-full bg-[#27272a] h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-white h-full rounded-full"
                    style={{
                      width: `${scanResult.breakdown.appMaliceScore !== undefined ? scanResult.breakdown.appMaliceScore : scanResult.breakdown.upiFraudIntentScore}%`
                    }}
                  />
                </div>
                <div className="text-[10px] text-[#71717a]">
                  {scanResult.breakdown.appMaliceScore !== undefined
                    ? 'Dangerous SMS & Accessibility permissions'
                    : 'Collect disguised as refund transaction'}
                </div>
              </div>
            </div>
          </div>

          {/* Extracted IOCs & Telemetry */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            {/* Extracted VPAs */}
            <div className="p-4 rounded-lg bg-[#121214] border border-[#27272a] space-y-2">
              <div className="text-white font-bold uppercase text-[11px]">Harvested Malicious UPI VPAs:</div>
              <div className="space-y-1">
                {scanResult.extractedVpa.map(vpa => (
                  <div key={vpa} className="p-2 rounded bg-[#000000] border border-[#27272a] text-[#e4e4e7] flex items-center justify-between">
                    <span>{vpa}</span>
                    <span className="text-[10px] text-[#a1a1aa] px-1.5 py-0.5 rounded bg-[#27272a]">FLAGGED VPA</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Campaign & Attribution */}
            <div className="p-4 rounded-lg bg-[#121214] border border-[#27272a] space-y-2">
              <div className="text-white font-bold uppercase text-[11px]">Campaign & Syndicate Attribution:</div>
              <div className="p-2.5 rounded bg-[#000000] border border-[#27272a] space-y-1">
                <div><span className="text-[#71717a]">Campaign:</span> <strong className="text-white">{scanResult.attributedCampaign}</strong></div>
                <div><span className="text-[#71717a]">Threat Actor:</span> <strong className="text-white">{scanResult.syndicate}</strong></div>
                <div><span className="text-[#71717a]">pHash Distance:</span> <span className="text-white">{scanResult.pHashDistance} bits</span> (SSIM: {(scanResult.structuralSSIM * 100).toFixed(1)}%)</div>
              </div>
            </div>
          </div>

          {/* Risk Reasons List */}
          <div className="p-4 rounded-lg bg-[#121214] border border-[#27272a] space-y-2 font-mono text-xs">
            <div className="text-white font-bold uppercase text-[11px]">Evidence & Detection Signals:</div>
            <ul className="space-y-1 text-[#d4d4d8]">
              {scanResult.riskReasons.map((reason, idx) => (
                <li key={idx} className="flex items-start space-x-2">
                  <span className="text-white">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Action Recommendation */}
          <div className="p-4 rounded-lg bg-[#000000] border border-white text-xs font-mono flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-[10px] text-[#a1a1aa] uppercase">Autonomous Action Directive:</div>
              <div className="text-white font-semibold mt-0.5">{scanResult.recommendedAction}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
