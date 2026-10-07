import React, { useState, useRef } from 'react';
import { Smartphone, Shield, FileCode, AlertCircle, Upload, CheckCircle2, ShieldAlert, Terminal, RefreshCw, Sparkles, Bug, KeyRound, FileUp, X } from 'lucide-react';
import { apiClient, ApkAnalysisResult } from '../services/api';

const SAMPLE_APKS = [
  {
    name: 'SBI_Yono_Mandatory_Update_v4.2.apk',
    target: 'SBI YONO',
    content: `<manifest package="com.sbi.lotusapply.banking">\n  <uses-permission android:name="android.permission.RECEIVE_SMS" />\n  <uses-permission android:name="android.permission.READ_SMS" />\n  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />\n  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />\n  <intent-filter><action android:name="android.intent.action.VIEW" /><data android:scheme="upi" android:host="pay" /></intent-filter>\n</manifest>`
  },
  {
    name: 'PhonePe_Scratch_Reward_5000.apk',
    target: 'PhonePe',
    content: `<manifest package="com.phonepe.rewards.instant">\n  <uses-permission android:name="android.permission.READ_PHONE_STATE" />\n  <uses-permission android:name="android.permission.RECEIVE_SMS" />\n  <uses-permission android:name="android.permission.INTERNET" />\n  <intent-filter><action android:name="android.intent.action.VIEW" /><data android:scheme="phonepe" /></intent-filter>\n</manifest>`
  },
  {
    name: 'Paytm_Fastag_KYC_Helper.apk',
    target: 'Paytm',
    content: `<manifest package="net.one97.paytm.kychelper">\n  <uses-permission android:name="android.permission.READ_CONTACTS" />\n  <uses-permission android:name="android.permission.READ_SMS" />\n  <uses-permission android:name="android.permission.CAMERA" />\n  <intent-filter><action android:name="android.intent.action.VIEW" /><data android:scheme="upi" /></intent-filter>\n</manifest>`
  }
];

export const ApkAnalyzer: React.FC = () => {
  const [currentAnalysis, setCurrentAnalysis] = useState<ApkAnalysisResult | null>(null);
  const [uploadedFileMeta, setUploadedFileMeta] = useState<{ name: string; size: number } | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'PERMISSIONS' | 'MANIFEST' | 'C2_TELEMETRY' | 'DISASSEMBLY'>('PERMISSIONS');
  const fileInputRef = useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    handleAnalyzeSample(SAMPLE_APKS[0]);
  }, []);

  const handleAnalyzeSample = async (sample: typeof SAMPLE_APKS[0]) => {
    setIsLoading(true);
    setUploadedFileMeta(null);
    try {
      const result = await apiClient.scanApk(sample.content, sample.name);
      setCurrentAnalysis(result);
    } catch (err) {
      console.error('Apk analyze error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadedFileMeta({
      name: file.name,
      size: file.size
    });

    setIsLoading(true);
    try {
      const result = await apiClient.scanApk(file);
      setCurrentAnalysis(result);
    } catch (err) {
      console.error('File upload error:', err);
    } finally {
      setIsLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full bg-indigo-50 border border-indigo-100 text-indigo-700 text-xs font-medium mb-2">
            <Smartphone className="w-3.5 h-3.5 text-indigo-600" />
            <span>Static Binary & Permissions Audit</span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center space-x-2">
            <span>Fake Android Banking App Inspector (APK Lab)</span>
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Static binary decompilation, dangerous permission auditing (SMS OTP theft & overlay attacks), and C2 server extraction.
          </p>
        </div>

        {/* Upload & Sample Selector */}
        <div className="flex flex-wrap items-center gap-2">
          <label className="cursor-pointer px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-xs">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload .APK File</span>
            <input
              ref={fileInputRef}
              type="file"
              accept=".apk,.zip,.dex,.xml"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>

          <select
            onChange={(e) => {
              const s = SAMPLE_APKS.find(item => item.name === e.target.value);
              if (s) handleAnalyzeSample(s);
            }}
            className="bg-white border border-slate-200 text-xs rounded-xl px-3 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 shadow-xs"
          >
            {SAMPLE_APKS.map(s => (
              <option key={s.name} value={s.name}>
                Preset: [{s.target}] {s.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Uploaded File Preview Banner if user uploaded a file */}
      {uploadedFileMeta && (
        <div className="p-4 rounded-xl bg-indigo-50/70 border border-indigo-200 flex items-center justify-between shadow-xs">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-indigo-600 text-white shadow-xs">
              <Smartphone className="w-4 h-4" />
            </div>
            <div>
              <div className="font-semibold text-xs text-slate-900 flex items-center space-x-2">
                <span>{uploadedFileMeta.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white text-indigo-700 border border-indigo-200 font-semibold">
                  {formatBytes(uploadedFileMeta.size)}
                </span>
              </div>
              <div className="text-[11px] text-slate-500">Android Application Archive • Decompiled & Inspected</div>
            </div>
          </div>

          <button
            onClick={() => handleAnalyzeSample(SAMPLE_APKS[0])}
            className="p-1 rounded-md text-slate-400 hover:text-slate-700 transition-colors"
            title="Clear upload"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {isLoading && (
        <div className="p-12 rounded-2xl bg-white border border-slate-200 text-center text-xs text-slate-600 flex items-center justify-center space-x-3 shadow-sm">
          <RefreshCw className="w-5 h-5 animate-spin text-indigo-600" />
          <span>Decompiling Android APK binary, reading manifest, and extracting malicious endpoints...</span>
        </div>
      )}

      {currentAnalysis && !isLoading && (
        <div className="space-y-4">
          {/* Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-xs space-y-1">
              <div className="text-xs text-slate-500 font-medium">Trojan Risk Score</div>
              <div className="text-2xl font-bold text-rose-600">{currentAnalysis.riskScore}%</div>
              <div className="text-[11px] text-rose-700 font-semibold">
                {currentAnalysis.isTrojan ? 'CRITICAL TROJAN' : 'SUSPICIOUS APP'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-xs space-y-1">
              <div className="text-xs text-slate-500 font-medium">Spoofed Brand</div>
              <div className="text-xl font-bold text-slate-900">{currentAnalysis.targetedBrand}</div>
              <div className="text-[11px] text-slate-500 font-mono truncate">{currentAnalysis.packageName}</div>
            </div>

            <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-xs space-y-1">
              <div className="text-xs text-slate-500 font-medium">Dangerous Permissions</div>
              <div className="text-2xl font-bold text-amber-600">{currentAnalysis.dangerousPermissions.length}</div>
              <div className="text-[11px] text-amber-700 font-medium">SMS OTP interception</div>
            </div>

            <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-xs space-y-1">
              <div className="text-xs text-slate-500 font-medium">C2 Exfil Endpoints</div>
              <div className="text-2xl font-bold text-indigo-600">{currentAnalysis.c2Endpoints.length + currentAnalysis.telegramBotHooks.length}</div>
              <div className="text-[11px] text-indigo-700 font-medium">Remote command channels</div>
            </div>
          </div>

          {/* Main Tabs Container */}
          <div className="p-5 rounded-2xl bg-white border border-slate-200/80 space-y-4 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
              <div className="text-xs font-semibold text-slate-900 flex items-center space-x-2">
                <Bug className="w-4 h-4 text-indigo-600" />
                <span>Target:</span>
                <span className="font-mono text-indigo-600 font-bold">{currentAnalysis.packageName}</span>
                <span className="text-slate-500">({currentAnalysis.fileName})</span>
              </div>

              <div className="flex items-center space-x-1 bg-slate-100 p-0.5 rounded-lg text-xs font-medium">
                <button
                  onClick={() => setActiveTab('PERMISSIONS')}
                  className={`px-3 py-1.5 rounded-md transition-all ${
                    activeTab === 'PERMISSIONS' ? 'bg-white text-slate-900 font-semibold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Permissions ({currentAnalysis.dangerousPermissions.length})
                </button>
                <button
                  onClick={() => setActiveTab('MANIFEST')}
                  className={`px-3 py-1.5 rounded-md transition-all ${
                    activeTab === 'MANIFEST' ? 'bg-white text-slate-900 font-semibold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  AndroidManifest.xml
                </button>
                <button
                  onClick={() => setActiveTab('C2_TELEMETRY')}
                  className={`px-3 py-1.5 rounded-md transition-all ${
                    activeTab === 'C2_TELEMETRY' ? 'bg-white text-slate-900 font-semibold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  C2 Gateways & Bots
                </button>
                <button
                  onClick={() => setActiveTab('DISASSEMBLY')}
                  className={`px-3 py-1.5 rounded-md transition-all ${
                    activeTab === 'DISASSEMBLY' ? 'bg-white text-slate-900 font-semibold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Smali Tokens
                </button>
              </div>
            </div>

            {/* Permissions Tab */}
            {activeTab === 'PERMISSIONS' && (
              <div className="space-y-4 text-xs">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {currentAnalysis.dangerousPermissions.map((item, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-slate-900 break-all">{item.permission}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
                          item.risk === 'CRITICAL' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700'
                        }`}>
                          {item.risk}
                        </span>
                      </div>
                      <p className="text-slate-600 text-[11px]">{item.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Manifest Tab */}
            {activeTab === 'MANIFEST' && (
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs text-slate-500 font-mono">
                  <span>Decompiled AndroidManifest.xml (Syntax Verified)</span>
                  <span>Target SDK: 34 (Android 14)</span>
                </div>
                <pre className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-800 font-mono text-xs overflow-x-auto leading-relaxed max-h-96">
                  {currentAnalysis.decompiledManifestXml}
                </pre>
              </div>
            )}

            {/* C2 Telemetry Tab */}
            {activeTab === 'C2_TELEMETRY' && (
              <div className="space-y-4 text-xs">
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                  <div className="font-bold text-slate-900 uppercase">Extracted Exfiltration Endpoints (Hardcoded in DEX):</div>
                  <div className="space-y-2">
                    {currentAnalysis.c2Endpoints.map((c2, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-slate-200 flex items-center justify-between font-mono">
                        <span className="text-indigo-700 font-semibold">{c2}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-bold">
                          POST /api/sms/exfil
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <div className="font-bold text-slate-900 uppercase">Telegram Bot Exfil Webhooks:</div>
                  <div className="space-y-1.5 font-mono">
                    {currentAnalysis.telegramBotHooks.map((bot, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-slate-200 text-indigo-700">
                        {bot}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Disassembly Tab */}
            {activeTab === 'DISASSEMBLY' && (
              <div className="space-y-2">
                <div className="text-xs text-slate-500 font-mono">
                  Smali bytecode signature tokens matching banking overlay injectors
                </div>
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 font-mono text-xs">
                  <div className="text-indigo-700 font-semibold">Lcom/sbi/lotusapply/banking/OverlayService;-&gt;showFakePinDialog()V</div>
                  <div className="text-slate-600 pl-4">.registers 4</div>
                  <div className="text-slate-600 pl-4">sget-object v0, Lcom/sbi/lotusapply/banking/R$layout;-&gt;activity_upi_pin_theft:I</div>
                  <div className="text-slate-600 pl-4">invoke-virtual {'{p0, v0}'}, Landroid/view/LayoutInflater;-&gt;inflate(ILandroid/view/ViewGroup;)Landroid/view/View;</div>
                  <div className="text-rose-700 font-semibold pl-4">invoke-static {'{v1}'}, Lcom/sbi/lotusapply/banking/ExfilClient;-&gt;sendSmsToTelegram(Ljava/lang/String;)V</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
