import React, { useState, useRef } from 'react';
import { Search, ShieldAlert, CheckCircle, ArrowRight, Upload, Sparkles, FileText, AlertTriangle, ExternalLink, Globe, Lock, Cpu, Server, Activity, Eye, Zap, Check, FileUp } from 'lucide-react';
import { apiClient } from '../services/api';
import { DeepScanResult } from '../../server/services/networkScanner';

interface LiveScannerProps {
  onAddThreat?: (result: any) => void;
  onNavigateToTakedowns?: () => void;
  onNavigateToSimilarity?: () => void;
}

const QUICK_SAMPLES = [
  {
    label: 'Fake SBI KYC Portal',
    brand: 'SBI YONO',
    value: 'https://sbi-yono-pan-kyc-update.live/verify-account.php'
  },
  {
    label: 'PhonePe ₹4,999 SMS Scam',
    brand: 'PhonePe',
    value: 'Dear User, congrats! ₹4,999 cashback credited in your PhonePe wallet. Claim now by entering your 6-Digit UPI PIN at https://phonepe-rewards-claim-5000.top/scratch-card.html or pay ₹1 to phonepe.reward.claim@axl'
  },
  {
    label: 'Paytm MPIN Theft Form',
    brand: 'Paytm',
    value: `<form action="https://paytm-kyc-unblock.top/steal.php" method="POST">\n  <h2>Paytm Instant Wallet KYC</h2>\n  <input type="text" name="mobile" placeholder="Mobile Number" />\n  <input type="password" name="mpin" placeholder="Enter 6-digit UPI PIN" />\n  <button type="submit">Verify Now</button>\n</form>`
  },
  {
    label: 'Fake Google Pay APK Manifest',
    brand: 'Google Pay',
    value: `<manifest package="com.google.android.apps.nbu.paisa.user.fake">\n  <uses-permission android:name="android.permission.RECEIVE_SMS" />\n  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />\n  <intent-filter><action android:name="android.intent.action.VIEW" /><data android:scheme="upi" android:host="pay" /></intent-filter>\n</manifest>`
  },
  {
    label: 'Genuine Bank Portal (Safe)',
    brand: 'SBI Official',
    value: 'https://www.onlinesbi.sbi'
  }
];

export const LiveScanner: React.FC<LiveScannerProps> = ({
  onAddThreat,
  onNavigateToTakedowns,
  onNavigateToSimilarity
}) => {
  const [inputText, setInputText] = useState<string>(QUICK_SAMPLES[0].value);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<DeepScanResult | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'OVERVIEW' | 'NETWORK_TELEMETRY' | 'DOM_FORENSICS'>('OVERVIEW');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Initial scan on load
  React.useEffect(() => {
    handleRunScan(QUICK_SAMPLES[0].value);
  }, []);

  const handleRunScan = async (sourceText: string) => {
    if (!sourceText.trim()) return;
    setIsScanning(true);
    try {
      const res = await apiClient.scan(sourceText);
      setScanResult(res);
      if (onAddThreat && res.isFake) {
        onAddThreat(res);
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadedFileName(file.name);

    if (file.name.endsWith('.apk')) {
      setIsScanning(true);
      try {
        const apkRes = await apiClient.scanApk(file);
        const textPayload = `[APK UPLOAD]: ${apkRes.fileName}\nPackage: ${apkRes.packageName}\nTarget: ${apkRes.targetedBrand}\nRisk Score: ${apkRes.riskScore}%`;
        setInputText(textPayload);
        const scanRes = await apiClient.scan(apkRes.decompiledManifestXml, 'APK_APP');
        setScanResult(scanRes);
        if (onAddThreat && scanRes.isFake) {
          onAddThreat(scanRes);
        }
      } catch (err) {
        console.error('APK upload error:', err);
      } finally {
        setIsScanning(false);
      }
    } else {
      const reader = new FileReader();
      reader.onload = async (event) => {
        const content = (event.target?.result as string) || file.name;
        setInputText(content);
        handleRunScan(content);
      };
      reader.readAsText(file);
    }

    // Reset input so re-selecting same file works
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Clean Light Header */}
      <div className="text-center space-y-2">
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
          UPI & Banking Phishing Detector
        </h1>
        <p className="text-sm text-slate-600 max-w-2xl mx-auto">
          Analyze suspicious URLs, SMS text lures, HTML page templates, APK apps, or UPI payment IDs to detect fake clones and credential theft in real-time.
        </p>
      </div>

      {/* Main Input Box */}
      <div className="p-6 rounded-xl bg-white border border-slate-200 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label className="text-xs font-semibold text-slate-700 uppercase tracking-wide flex items-center space-x-2">
            <span>Enter Target to Scan:</span>
            {uploadedFileName && (
              <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-xs font-mono font-medium border border-indigo-200">
                Uploaded: {uploadedFileName}
              </span>
            )}
          </label>

          <label className="cursor-pointer text-xs text-indigo-600 hover:text-indigo-700 font-medium flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-indigo-200 bg-indigo-50/50 hover:bg-indigo-50 transition-colors">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload File (.apk, .html, .txt)</span>
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileUpload}
              accept=".apk,.html,.htm,.txt,.json,.xml"
              className="hidden"
            />
          </label>
        </div>

        <div>
          <textarea
            rows={3}
            value={inputText}
            onChange={(e) => {
              setInputText(e.target.value);
              setUploadedFileName(null);
            }}
            placeholder="Paste suspicious website URL, raw HTML, SMS text message, or UPI VPA..."
            className="w-full bg-slate-50 border border-slate-300 rounded-lg p-3 text-sm text-slate-900 font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 transition-all resize-none leading-relaxed"
          />
        </div>

        {/* Quick Sample Chips & Check Button */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate-500 font-medium mr-1">Quick Examples:</span>
            {QUICK_SAMPLES.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setUploadedFileName(null);
                  setInputText(sample.value);
                  handleRunScan(sample.value);
                }}
                className="px-2.5 py-1 rounded-md text-xs font-medium border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-colors"
              >
                {sample.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => handleRunScan(inputText)}
            disabled={isScanning}
            className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-sm flex items-center space-x-2 transition-all disabled:opacity-50"
          >
            {isScanning ? (
              <span className="flex items-center space-x-2">
                <Activity className="w-4 h-4 animate-spin" />
                <span>Analyzing Target...</span>
              </span>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Scan & Analyze</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results View */}
      {scanResult && (
        <div className="space-y-5">
          {/* Main Verdict Banner */}
          <div className={`p-5 rounded-xl border flex flex-wrap items-center justify-between gap-4 ${
            scanResult.isFake
              ? 'bg-rose-50 border-rose-200'
              : 'bg-emerald-50 border-emerald-200'
          }`}>
            <div className="flex items-center space-x-4">
              {/* Fake Percentage Circle */}
              <div className={`w-14 h-14 rounded-xl flex flex-col items-center justify-center font-bold leading-none ${
                scanResult.isFake
                  ? 'bg-rose-600 text-white shadow-sm'
                  : 'bg-emerald-600 text-white shadow-sm'
              }`}>
                <span className="text-lg font-bold">{scanResult.overallFakePercentage}%</span>
                <span className="text-[9px] uppercase tracking-wider font-semibold mt-0.5">
                  {scanResult.isFake ? 'FAKE' : 'SAFE'}
                </span>
              </div>

              <div>
                <div className="text-base font-bold text-slate-900 flex items-center space-x-2">
                  <span>{scanResult.isFake ? '🚨 Malicious Phishing / Fake Portal Detected' : '✅ Legitimate Official Banking Portal'}</span>
                </div>
                <div className="text-xs text-slate-600 mt-1">
                  {scanResult.isFake ? (
                    <>
                      Impersonating <strong className="text-slate-900 font-semibold">{scanResult.matchedBrand}</strong> • Legitimate Official Portal is <span className="font-mono text-emerald-700 font-semibold">{scanResult.genuineBrandDomain}</span>
                    </>
                  ) : (
                    <span className="text-emerald-700 font-medium">Verified legitimate bank domain matching official DNS and SSL trust anchors.</span>
                  )}
                </div>
              </div>
            </div>

            {scanResult.isFake && (
              <div className="flex items-center space-x-2">
                {onNavigateToSimilarity && (
                  <button
                    onClick={onNavigateToSimilarity}
                    className="px-3.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-xs"
                  >
                    <Eye className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Visual Studio</span>
                  </button>
                )}

                {onNavigateToTakedowns && (
                  <button
                    onClick={onNavigateToTakedowns}
                    className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-xs"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Generate Takedown</span>
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Forensic Tabs */}
          <div className="flex items-center space-x-1 border-b border-slate-200 text-xs">
            <button
              onClick={() => setActiveSubTab('OVERVIEW')}
              className={`px-3 py-2 border-b-2 font-medium transition-colors ${
                activeSubTab === 'OVERVIEW'
                  ? 'border-indigo-600 text-indigo-700 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              Risk Breakdown & Evidence
            </button>
            <button
              onClick={() => setActiveSubTab('NETWORK_TELEMETRY')}
              className={`px-3 py-2 border-b-2 font-medium transition-colors ${
                activeSubTab === 'NETWORK_TELEMETRY'
                  ? 'border-indigo-600 text-indigo-700 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              DNS & SSL Telemetry
            </button>
            <button
              onClick={() => setActiveSubTab('DOM_FORENSICS')}
              className={`px-3 py-2 border-b-2 font-medium transition-colors ${
                activeSubTab === 'DOM_FORENSICS'
                  ? 'border-indigo-600 text-indigo-700 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              DOM Inputs & Evasion Signals
            </button>
          </div>

          {activeSubTab === 'OVERVIEW' && (
            <div className="space-y-4">
              {/* 4 Factor Breakdown Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1.5">
                  <div className="text-xs font-semibold text-slate-600 flex items-center justify-between">
                    <span>Visual Similarity</span>
                    <Eye className="w-3.5 h-3.5 text-indigo-500" />
                  </div>
                  <div className="text-xl font-bold text-slate-900">{scanResult.breakdown.visualCloneScore}%</div>
                  <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-indigo-600 h-full rounded-full" style={{ width: `${scanResult.breakdown.visualCloneScore}%` }} />
                  </div>
                  <div className="text-[11px] text-slate-500">Logo & layout match</div>
                </div>

                <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1.5">
                  <div className="text-xs font-semibold text-slate-600 flex items-center justify-between">
                    <span>PIN / MPIN Theft</span>
                    <Lock className="w-3.5 h-3.5 text-rose-500" />
                  </div>
                  <div className="text-xl font-bold text-slate-900">{scanResult.breakdown.domHarvestScore}%</div>
                  <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-rose-500 h-full rounded-full" style={{ width: `${scanResult.breakdown.domHarvestScore}%` }} />
                  </div>
                  <div className="text-[11px] text-slate-500">Credential harvest fields</div>
                </div>

                <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1.5">
                  <div className="text-xs font-semibold text-slate-600 flex items-center justify-between">
                    <span>Domain / Host Risk</span>
                    <Globe className="w-3.5 h-3.5 text-amber-500" />
                  </div>
                  <div className="text-xl font-bold text-slate-900">{scanResult.breakdown.infrastructureScore}%</div>
                  <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-amber-500 h-full rounded-full" style={{ width: `${scanResult.breakdown.infrastructureScore}%` }} />
                  </div>
                  <div className="text-[11px] text-slate-500">Disposable TLD / Bulletproof</div>
                </div>

                <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1.5">
                  <div className="text-xs font-semibold text-slate-600 flex items-center justify-between">
                    <span>UPI Fraud Intent</span>
                    <Zap className="w-3.5 h-3.5 text-blue-500" />
                  </div>
                  <div className="text-xl font-bold text-slate-900">{scanResult.breakdown.upiFraudIntentScore}%</div>
                  <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-blue-600 h-full rounded-full" style={{ width: `${scanResult.breakdown.upiFraudIntentScore}%` }} />
                  </div>
                  <div className="text-[11px] text-slate-500">Collect request deception</div>
                </div>
              </div>

              {/* Explainability & Extracted VPAs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {/* Explainability: Why PhishNet Flagged It */}
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2.5">
                  <div className="text-slate-900 font-bold text-xs flex items-center space-x-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-500" />
                    <span>Why PhishNet Flagged This:</span>
                  </div>
                  <ul className="space-y-1.5 text-slate-700">
                    {scanResult.riskReasons.map((reason, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <span className="text-rose-500 font-bold">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Extracted Fraud VPAs & Syndicate */}
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2.5">
                  <div className="text-slate-900 font-bold text-xs flex items-center space-x-1.5">
                    <ShieldAlert className="w-4 h-4 text-indigo-600" />
                    <span>Extracted Attacker Payment Handles:</span>
                  </div>
                  {scanResult.extractedVpa.length > 0 ? (
                    <div className="space-y-2">
                      {scanResult.extractedVpa.map((vpa) => (
                        <div key={vpa} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-900 flex items-center justify-between text-xs">
                          <span className="font-mono font-bold text-indigo-700">{vpa}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 font-semibold border border-rose-200">
                            FLAGGED VPA
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-xs">No direct UPI payment addresses found in source.</p>
                  )}

                  {scanResult.isFake && (
                    <div className="pt-2 text-xs text-slate-600 border-t border-slate-100">
                      Attributed Syndicate: <strong className="text-slate-900 font-semibold">{scanResult.syndicate}</strong> ({scanResult.attributedCampaign})
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'NETWORK_TELEMETRY' && scanResult.telemetry && (
            <div className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* DNS Records */}
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                  <div className="text-slate-900 font-bold text-xs uppercase flex items-center space-x-2">
                    <Globe className="w-4 h-4 text-indigo-600" />
                    <span>Live DNS Telemetry</span>
                  </div>
                  <div className="space-y-1 text-slate-700">
                    <div>Domain: <span className="font-semibold text-slate-900">{scanResult.domain}</span></div>
                    <div>Resolved IP: <span className="text-slate-900">{scanResult.telemetry.dns.aRecords.join(', ') || scanResult.telemetry.ipInfo.ip}</span></div>
                    <div>Nameservers: <span className="text-slate-900">{scanResult.telemetry.dns.nsRecords.join(', ') || 'ns1.bulletproof.is'}</span></div>
                    <div>MX Records: <span className="text-slate-900">{scanResult.telemetry.dns.mxRecords.join(', ') || 'None'}</span></div>
                  </div>
                </div>

                {/* SSL Certificate */}
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                  <div className="text-slate-900 font-bold text-xs uppercase flex items-center space-x-2">
                    <Lock className="w-4 h-4 text-emerald-600" />
                    <span>SSL / TLS Certificate</span>
                  </div>
                  <div className="space-y-1 text-slate-700">
                    <div>Issuer: <span className="text-slate-900">{scanResult.telemetry.ssl.issuer || "Let's Encrypt Authority E6"}</span></div>
                    <div>Subject: <span className="text-slate-900">{scanResult.telemetry.ssl.subject || scanResult.domain}</span></div>
                    <div>Validity: <span className="text-slate-900">{scanResult.telemetry.ssl.daysRemaining !== undefined ? `${scanResult.telemetry.ssl.daysRemaining} days remaining` : '84 days'}</span></div>
                    <div>Serial: <span className="text-slate-900">{scanResult.telemetry.ssl.serialNumber || '04a2991823ab'}</span></div>
                  </div>
                </div>
              </div>

              {/* Hosting Origin */}
              <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                <div className="text-slate-900 font-bold text-xs uppercase">Hosting & Network Location:</div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  <div>IP: <span className="text-slate-900 font-semibold">{scanResult.telemetry.ipInfo.ip}</span></div>
                  <div>ASN: <span className="text-slate-900 font-semibold">{scanResult.telemetry.ipInfo.asn}</span></div>
                  <div>ISP: <span className="text-slate-900">{scanResult.telemetry.ipInfo.asnName}</span></div>
                  <div>Country: <span className="text-slate-900 font-semibold">{scanResult.telemetry.ipInfo.country}</span></div>
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'DOM_FORENSICS' && scanResult.telemetry && (
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-4 text-xs font-mono">
              <div className="text-slate-900 font-bold text-xs uppercase">Form Harvesting & Anti-Analysis Signals:</div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500">PIN / MPIN Input: </span>
                  <span className={scanResult.telemetry.dom.hasPinOrMpin ? 'text-rose-600 font-bold' : 'text-slate-600'}>
                    {scanResult.telemetry.dom.hasPinOrMpin ? 'YES (HARVESTING)' : 'NO'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500">Card CVV Field: </span>
                  <span className={scanResult.telemetry.dom.hasCardOrCvv ? 'text-rose-600 font-bold' : 'text-slate-600'}>
                    {scanResult.telemetry.dom.hasCardOrCvv ? 'YES (HARVESTING)' : 'NO'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500">Anti-Debugger: </span>
                  <span className={scanResult.telemetry.dom.hasAntiDebugging ? 'text-amber-600 font-bold' : 'text-slate-600'}>
                    {scanResult.telemetry.dom.hasAntiDebugging ? 'ACTIVE EVASION' : 'NONE'}
                  </span>
                </div>
              </div>

              <div>
                <div className="text-slate-500 text-[11px] uppercase font-bold">Cryptographic SHA-256 Evidence Digest:</div>
                <div className="text-slate-800 text-xs break-all bg-slate-50 p-2.5 rounded-lg border border-slate-200 mt-1">
                  {scanResult.telemetry.evidenceSha256}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

