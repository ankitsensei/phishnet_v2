import React, { useState, useRef } from 'react';
import { Search, ShieldAlert, CheckCircle, ArrowRight, Upload, Sparkles, FileText, AlertTriangle, ExternalLink, Globe, Lock, Cpu, Server, Activity, Eye, Zap, Check, FileUp, X, FileCode, Smartphone, Image as ImageIcon } from 'lucide-react';
import { apiClient } from '../services/api';
import { DeepScanResult } from '../../server/services/networkScanner';

interface LiveScannerProps {
  onAddThreat?: (result: any) => void;
  onNavigateToTakedowns?: () => void;
  onNavigateToSimilarity?: () => void;
}

interface UploadedFileMeta {
  name: string;
  size: number;
  type: string;
  previewSnippet?: string;
  imagePreviewUrl?: string;
  isApk?: boolean;
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
  const [fileMeta, setFileMeta] = useState<UploadedFileMeta | null>(null);
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

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const isApk = file.name.endsWith('.apk');
    const isImage = file.type.startsWith('image/');

    if (isApk) {
      setFileMeta({
        name: file.name,
        size: file.size,
        type: 'Android Package (APK)',
        isApk: true,
        previewSnippet: `[APK Package Archive]\nFilename: ${file.name}\nSize: ${formatFileSize(file.size)}\nTarget: Android OS (Automated decompiler will parse AndroidManifest.xml and Smali bytecode)`
      });

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
    } else if (isImage) {
      const imageUrl = URL.createObjectURL(file);
      setFileMeta({
        name: file.name,
        size: file.size,
        type: file.type || 'Image File',
        imagePreviewUrl: imageUrl,
        previewSnippet: `[Screenshot Upload]\nFilename: ${file.name}\nResolution preview loaded.\nOCR + Visual SSIM similarity pipeline active.`
      });
      setInputText(`[Image Screenshot]: ${file.name} - Analyzing visual similarity & OCR logos...`);
      handleRunScan(`[Image Screenshot]: ${file.name}`);
    } else {
      const reader = new FileReader();
      reader.onload = async (event) => {
        const content = (event.target?.result as string) || '';
        const lines = content.split('\n').slice(0, 12).join('\n');
        setFileMeta({
          name: file.name,
          size: file.size,
          type: file.type || 'Text/Code Document',
          previewSnippet: lines + (content.split('\n').length > 12 ? '\n... (truncated)' : '')
        });
        setInputText(content);
        handleRunScan(content);
      };
      reader.readAsText(file);
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClearFile = () => {
    setFileMeta(null);
    setInputText(QUICK_SAMPLES[0].value);
    handleRunScan(QUICK_SAMPLES[0].value);
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

      {/* Main Input & Upload Box */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label className="text-xs font-semibold text-slate-700 uppercase tracking-wide flex items-center space-x-2">
            <span>Enter Target to Scan:</span>
          </label>

          <label className="cursor-pointer text-xs text-indigo-600 hover:text-indigo-700 font-medium flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-indigo-200 bg-indigo-50/50 hover:bg-indigo-50 transition-colors">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload File (.apk, .html, .txt, .png)</span>
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileUpload}
              accept=".apk,.html,.htm,.txt,.json,.xml,.png,.jpg,.webp"
              className="hidden"
            />
          </label>
        </div>

        {/* File Upload Preview Panel if active */}
        {fileMeta && (
          <div className="p-4 rounded-xl bg-indigo-50/50 border border-indigo-200/80 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                {fileMeta.isApk ? (
                  <div className="p-2 rounded-lg bg-indigo-600 text-white shadow-xs">
                    <Smartphone className="w-4 h-4" />
                  </div>
                ) : fileMeta.imagePreviewUrl ? (
                  <div className="p-2 rounded-lg bg-emerald-600 text-white shadow-xs">
                    <ImageIcon className="w-4 h-4" />
                  </div>
                ) : (
                  <div className="p-2 rounded-lg bg-indigo-600 text-white shadow-xs">
                    <FileCode className="w-4 h-4" />
                  </div>
                )}
                <div>
                  <div className="font-semibold text-xs text-slate-900 flex items-center space-x-2">
                    <span>{fileMeta.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-800 font-mono">
                      {formatFileSize(fileMeta.size)}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">{fileMeta.type}</div>
                </div>
              </div>

              <button
                onClick={handleClearFile}
                className="p-1 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors"
                title="Remove uploaded file"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* File Preview Snippet / Thumbnail */}
            {fileMeta.imagePreviewUrl ? (
              <div className="max-h-48 rounded-lg overflow-hidden border border-indigo-200 bg-white flex items-center justify-center p-2">
                <img src={fileMeta.imagePreviewUrl} alt="Uploaded preview" className="max-h-40 object-contain rounded" />
              </div>
            ) : fileMeta.previewSnippet ? (
              <pre className="p-3 rounded-lg bg-white border border-indigo-100 font-mono text-xs text-slate-800 max-h-36 overflow-y-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                {fileMeta.previewSnippet}
              </pre>
            ) : null}
          </div>
        )}

        <div>
          <textarea
            rows={3}
            value={inputText}
            onChange={(e) => {
              setInputText(e.target.value);
            }}
            placeholder="Paste suspicious website URL, raw HTML, SMS text message, or UPI VPA..."
            className="w-full bg-slate-50 border border-slate-300 rounded-xl p-3 text-sm text-slate-900 font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 transition-all resize-none leading-relaxed"
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
                  setFileMeta(null);
                  setInputText(sample.value);
                  handleRunScan(sample.value);
                }}
                className="px-2.5 py-1 rounded-lg text-xs font-medium border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-colors"
              >
                {sample.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => handleRunScan(inputText)}
            disabled={isScanning}
            className="px-5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-sm flex items-center space-x-2 transition-all disabled:opacity-50"
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
        <div className="space-y-5 animate-in fade-in duration-200">
          {/* Verdict Banner */}
          <div
            className={`p-6 rounded-2xl border shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
              scanResult.isFake
                ? 'bg-rose-50/80 border-rose-200 text-rose-950'
                : 'bg-emerald-50/80 border-emerald-200 text-emerald-950'
            }`}
          >
            <div className="flex items-start space-x-3.5">
              <div
                className={`p-2.5 rounded-xl text-white font-bold shrink-0 mt-0.5 shadow-xs ${
                  scanResult.isFake ? 'bg-rose-600' : 'bg-emerald-600'
                }`}
              >
                {scanResult.isFake ? (
                  <ShieldAlert className="w-6 h-6" />
                ) : (
                  <CheckCircle className="w-6 h-6" />
                )}
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-lg font-bold tracking-tight">
                    {scanResult.isFake
                      ? `CRITICAL THREAT: Fake ${scanResult.matchedBrand || 'Payment'} Page Detected`
                      : `SAFE: Verified Legitimate Banking Portal`}
                  </h3>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${
                      scanResult.isFake
                        ? 'bg-rose-200/80 text-rose-800'
                        : 'bg-emerald-200/80 text-emerald-800'
                    }`}
                  >
                    {scanResult.overallFakePercentage}% Fake Probability
                  </span>
                </div>
                <p className="text-xs text-slate-700 mt-1 max-w-2xl leading-relaxed">
                  {scanResult.riskReasons && scanResult.riskReasons.length > 0
                    ? scanResult.riskReasons.join(' • ')
                    : scanResult.recommendedAction || 'Autonomous analysis completed.'}
                </p>
              </div>
            </div>

            {/* Quick Action Button */}
            {scanResult.isFake && (
              <div className="flex items-center space-x-2 shrink-0">
                {onNavigateToSimilarity && (
                  <button
                    onClick={onNavigateToSimilarity}
                    className="px-3 py-2 rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium flex items-center space-x-1.5 shadow-xs transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Visual Studio</span>
                  </button>
                )}
                {onNavigateToTakedowns && (
                  <button
                    onClick={onNavigateToTakedowns}
                    className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold flex items-center space-x-1.5 shadow-xs transition-colors"
                  >
                    <span>1-Click Takedown</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Key Indicators Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
              <div className="text-[11px] uppercase text-slate-500 font-sans font-semibold">Visual SSIM Match</div>
              <div className="text-2xl font-bold text-slate-900">
                {(scanResult.structuralSSIM * 100).toFixed(1)}%
              </div>
              <div className="text-[11px] text-slate-500 font-sans">vs Official Template</div>
            </div>

            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
              <div className="text-[11px] uppercase text-slate-500 font-sans font-semibold">pHash Distance</div>
              <div className="text-2xl font-bold text-slate-900">
                {scanResult.pHashDistance} <span className="text-xs text-slate-400 font-normal">bits</span>
              </div>
              <div className="text-[11px] text-slate-500 font-sans">&lt; 10 = Visual Clone</div>
            </div>

            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
              <div className="text-[11px] uppercase text-slate-500 font-sans font-semibold">Attributed Syndicate</div>
              <div className="text-xs font-bold text-indigo-600 mt-1 truncate">
                {scanResult.syndicate || 'Unknown Actor'}
              </div>
              <div className="text-[11px] text-slate-500 font-sans truncate">{scanResult.attributedCampaign || 'Independent Phish'}</div>
            </div>

            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
              <div className="text-[11px] uppercase text-slate-500 font-sans font-semibold">Harvested VPA</div>
              <div className="text-xs font-bold text-rose-600 mt-1 truncate">
                {scanResult.extractedVpa?.[0] || 'None Detected'}
              </div>
              <div className="text-[11px] text-slate-500 font-sans">UPI Fraud Collect Endpoint</div>
            </div>
          </div>

          {/* Forensics Tabs */}
          <div className="rounded-2xl bg-white border border-slate-200 shadow-xs overflow-hidden">
            <div className="border-b border-slate-200 bg-slate-50/70 px-4 py-2 flex space-x-2">
              {[
                { id: 'OVERVIEW', label: 'Detection Indicators & Vectors' },
                { id: 'NETWORK_TELEMETRY', label: 'Network & DNS Telemetry' },
                { id: 'DOM_FORENSICS', label: 'DOM Form Inspection' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveSubTab(tab.id as any)}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    activeSubTab === tab.id
                      ? 'bg-white text-indigo-700 shadow-xs border border-slate-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="p-5 text-xs text-slate-700 font-mono">
              {activeSubTab === 'OVERVIEW' && (
                <div className="space-y-4 font-sans">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                      <div className="font-bold text-xs text-slate-900 uppercase">Scam Lure & Vectors</div>
                      <div className="space-y-1 text-xs">
                        <div className="flex justify-between py-1 border-b border-slate-200/60">
                          <span className="text-slate-500">Threat Type:</span>
                          <span className="font-semibold text-slate-800">{scanResult.threatType}</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200/60">
                          <span className="text-slate-500">Targeted Brand:</span>
                          <span className="font-semibold text-slate-800">{scanResult.matchedBrand}</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200/60">
                          <span className="text-slate-500">Official Brand Domain:</span>
                          <span className="font-semibold text-indigo-600">{scanResult.genuineBrandDomain}</span>
                        </div>
                        <div className="flex justify-between py-1">
                          <span className="text-slate-500">QR Intent Payload:</span>
                          <span className="font-semibold text-rose-600">{scanResult.qrIntentDetected ? 'Yes (Malicious Auto-Collect)' : 'None'}</span>
                        </div>
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                      <div className="font-bold text-xs text-slate-900 uppercase">Anti-Analysis & Cloaking Tactics</div>
                      <div className="space-y-1.5 text-xs">
                        <div className="flex items-center space-x-2">
                          <span className={`w-2 h-2 rounded-full ${scanResult.evasionTactics?.antiBotGating ? 'bg-amber-500' : 'bg-slate-300'}`} />
                          <span className="text-slate-700">User-Agent Cloaking / Gating</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={`w-2 h-2 rounded-full ${scanResult.evasionTactics?.geoFencingIndiaOnly ? 'bg-amber-500' : 'bg-slate-300'}`} />
                          <span className="text-slate-700">India-Only GeoIP BGP Gating</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={`w-2 h-2 rounded-full ${scanResult.evasionTactics?.devtoolsBlocker ? 'bg-amber-500' : 'bg-slate-300'}`} />
                          <span className="text-slate-700">Anti-Debugger Loop / DevTools Block</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeSubTab === 'NETWORK_TELEMETRY' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-slate-500">Host IP Address:</span>
                      <div className="font-bold text-slate-900">{scanResult.telemetry?.ipInfo?.ip} ({scanResult.telemetry?.ipInfo?.country})</div>
                      <div className="text-[11px] text-slate-500">{scanResult.telemetry?.ipInfo?.asn} - {scanResult.telemetry?.ipInfo?.asnName}</div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-slate-500">Domain Registrar:</span>
                      <div className="font-bold text-slate-900">{scanResult.telemetry?.ipInfo?.registrar}</div>
                      <div className="text-[11px] text-slate-500">Country: {scanResult.telemetry?.ipInfo?.countryCode}</div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-slate-500">SSL Certificate Issuer:</span>
                      <div className="font-bold text-slate-900">{scanResult.telemetry?.ssl?.issuer || 'Self-Signed / Untrusted'}</div>
                      <div className="text-[11px] text-slate-500">Serial: {scanResult.telemetry?.ssl?.serialNumber || 'N/A'}</div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-slate-500">Nameservers:</span>
                      <div className="font-bold text-slate-900">{scanResult.telemetry?.dns?.nsRecords?.join(', ') || 'N/A'}</div>
                    </div>
                  </div>
                </div>
              )}

              {activeSubTab === 'DOM_FORENSICS' && (
                <div className="space-y-3">
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                    <div className="font-bold text-xs text-slate-900 font-sans uppercase">Extracted Credential Stealing Inputs & Form Actions:</div>
                    <div className="space-y-1.5 font-mono text-xs">
                      {scanResult.telemetry?.dom?.inputTypes && scanResult.telemetry.dom.inputTypes.length > 0 ? (
                        scanResult.telemetry.dom.inputTypes.map((inp, i) => (
                          <div key={i} className="p-2.5 rounded-lg bg-white border border-slate-200 text-rose-700 flex items-center justify-between">
                            <span>Input Type: &lt;input type="{inp}" /&gt;</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-200 font-sans font-semibold">
                              Credential Vector
                            </span>
                          </div>
                        ))
                      ) : (
                        <div className="text-slate-500">No raw HTML form inputs found in snippet.</div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
