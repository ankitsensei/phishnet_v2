import React, { useState } from 'react';
import { Smartphone, Shield, FileCode, AlertCircle, Upload, CheckCircle2, ShieldAlert, Terminal, RefreshCw } from 'lucide-react';
import { apiClient } from '../services/api';
import { ApkAnalysisResult } from '../../server/services/apkInspector';

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
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'PERMISSIONS' | 'MANIFEST' | 'C2_TELEMETRY' | 'DISASSEMBLY'>('PERMISSIONS');

  React.useEffect(() => {
    handleAnalyzeSample(SAMPLE_APKS[0]);
  }, []);

  const handleAnalyzeSample = async (sample: typeof SAMPLE_APKS[0]) => {
    setIsLoading(true);
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

    setIsLoading(true);
    try {
      const result = await apiClient.scanApk(file);
      setCurrentAnalysis(result);
    } catch (err) {
      console.error('File upload error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#222226] flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight flex items-center space-x-2">
            <Smartphone className="w-4 h-4 text-white" />
            <span>Android Banking Trojan & Malicious APK Lab</span>
          </h2>
          <p className="text-xs text-[#888892] mt-0.5">
            Static binary decompilation, dangerous SMS/Accessibility permissions, overlay attack detection, and C2 exfiltration extraction.
          </p>
        </div>

        {/* Upload & Sample Selector */}
        <div className="flex flex-wrap items-center gap-2 font-mono">
          <label className="cursor-pointer px-3 py-1.5 rounded-md bg-white text-black hover:bg-[#e4e4e7] text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-sm">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Real APK / ZIP</span>
            <input type="file" accept=".apk,.zip,.dex,.xml" onChange={handleFileUpload} className="hidden" />
          </label>

          <select
            onChange={(e) => {
              const s = SAMPLE_APKS.find(item => item.name === e.target.value);
              if (s) handleAnalyzeSample(s);
            }}
            className="bg-[#121214] border border-[#222226] text-xs rounded-md px-3 py-1.5 text-white focus:outline-none focus:border-white"
          >
            {SAMPLE_APKS.map(s => (
              <option key={s.name} value={s.name}>
                [{s.target}] {s.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && (
        <div className="p-8 rounded-lg bg-[#09090b] border border-[#222226] text-center font-mono text-xs text-[#888892] flex items-center justify-center space-x-2">
          <RefreshCw className="w-4 h-4 animate-spin text-white" />
          <span>Decompiling Android APK binary and inspecting manifest permissions...</span>
        </div>
      )}

      {currentAnalysis && !isLoading && (
        <div className="space-y-4 animate-in fade-in duration-150">
          {/* Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
              <div className="text-[11px] uppercase text-[#71717a]">Trojan Risk Score</div>
              <div className="text-2xl font-bold text-white mt-1">{currentAnalysis.riskScore}%</div>
              <div className="text-[10px] text-white mt-0.5 font-bold">
                {currentAnalysis.isTrojan ? 'CRITICAL TROJAN' : 'SUSPICIOUS APP'}
              </div>
            </div>

            <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
              <div className="text-[11px] uppercase text-[#71717a]">Target Spoofed</div>
              <div className="text-lg font-bold text-white mt-1">{currentAnalysis.targetedBrand}</div>
              <div className="text-[10px] text-[#71717a] truncate mt-0.5">{currentAnalysis.packageName}</div>
            </div>

            <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
              <div className="text-[11px] uppercase text-[#71717a]">Dangerous Perms</div>
              <div className="text-2xl font-bold text-white mt-1">{currentAnalysis.dangerousPermissions.length}</div>
              <div className="text-[10px] text-[#71717a] mt-0.5">SMS & Keylogging abuse</div>
            </div>

            <div className="p-4 rounded-lg bg-[#09090b] border border-[#222226]">
              <div className="text-[11px] uppercase text-[#71717a]">C2 & Bots</div>
              <div className="text-2xl font-bold text-white mt-1">{currentAnalysis.c2Endpoints.length + currentAnalysis.telegramBotHooks.length}</div>
              <div className="text-[10px] text-[#71717a] mt-0.5">Exfiltration channels</div>
            </div>
          </div>

          {/* Main Tabs Container */}
          <div className="p-5 rounded-lg bg-[#09090b] border border-[#222226] space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222226] pb-3">
              <div className="text-xs font-mono font-bold text-white uppercase">
                Static Forensics: {currentAnalysis.packageName} ({currentAnalysis.fileName})
              </div>

              <div className="flex items-center space-x-1 bg-[#121214] p-1 rounded-md border border-[#222226] text-xs font-mono">
                <button
                  onClick={() => setActiveTab('PERMISSIONS')}
                  className={`px-3 py-1 rounded font-medium transition-colors ${
                    activeTab === 'PERMISSIONS' ? 'bg-white text-black font-semibold' : 'text-[#888892] hover:text-white'
                  }`}
                >
                  Permissions ({currentAnalysis.dangerousPermissions.length})
                </button>
                <button
                  onClick={() => setActiveTab('MANIFEST')}
                  className={`px-3 py-1 rounded font-medium transition-colors ${
                    activeTab === 'MANIFEST' ? 'bg-white text-black font-semibold' : 'text-[#888892] hover:text-white'
                  }`}
                >
                  AndroidManifest.xml
                </button>
                <button
                  onClick={() => setActiveTab('C2_TELEMETRY')}
                  className={`px-3 py-1 rounded font-medium transition-colors ${
                    activeTab === 'C2_TELEMETRY' ? 'bg-white text-black font-semibold' : 'text-[#888892] hover:text-white'
                  }`}
                >
                  C2 Gateways & Bots
                </button>
                <button
                  onClick={() => setActiveTab('DISASSEMBLY')}
                  className={`px-3 py-1 rounded font-medium transition-colors ${
                    activeTab === 'DISASSEMBLY' ? 'bg-white text-black font-semibold' : 'text-[#888892] hover:text-white'
                  }`}
                >
                  Smali Tokens
                </button>
              </div>
            </div>

            {/* Permissions Tab */}
            {activeTab === 'PERMISSIONS' && (
              <div className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {currentAnalysis.dangerousPermissions.map((item, idx) => (
                    <div key={idx} className="p-3 rounded bg-[#121214] border border-[#222226] space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white break-all">{item.permission}</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-white text-black font-bold">
                          {item.risk}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#888892]">{item.description}</div>
                    </div>
                  ))}
                </div>

                <div className="p-3.5 rounded bg-[#000000] border border-[#222226] space-y-1.5 text-xs">
                  <div className="text-white font-bold uppercase text-[11px]">Malicious UPI Intent Hooks Detected:</div>
                  {currentAnalysis.intentFilters.map((intent, idx) => (
                    <div key={idx} className="p-1.5 rounded bg-[#121214] border border-[#222226] text-[#d4d4d8]">
                      {intent}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Android Manifest Tab */}
            {activeTab === 'MANIFEST' && (
              <pre className="p-4 rounded bg-[#000000] border border-[#222226] font-mono text-xs text-[#d4d4d8] overflow-x-auto leading-relaxed max-h-96">
                {currentAnalysis.decompiledManifestXml}
              </pre>
            )}

            {/* C2 Telemetry Tab */}
            {activeTab === 'C2_TELEMETRY' && (
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3.5 rounded bg-[#000000] border border-[#222226] space-y-2">
                  <div className="text-white font-bold uppercase text-[11px]">Hardcoded C2 Data Exfiltration Endpoints:</div>
                  {currentAnalysis.c2Endpoints.map((ep, idx) => (
                    <div key={idx} className="p-2 rounded bg-[#121214] border border-[#222226] text-white break-all">
                      POST {ep}
                    </div>
                  ))}
                </div>

                <div className="p-3.5 rounded bg-[#000000] border border-[#222226] space-y-2">
                  <div className="text-white font-bold uppercase text-[11px]">Telegram Bot Exfiltration Hooks:</div>
                  {currentAnalysis.telegramBotHooks.map((bot, idx) => (
                    <div key={idx} className="p-2 rounded bg-[#121214] border border-[#222226] text-white break-all">
                      {bot}
                    </div>
                  ))}
                </div>

                <div className="p-3.5 rounded bg-[#000000] border border-[#222226] space-y-1">
                  <div className="text-[#71717a] text-[10px] uppercase">SHA-256 File Hash:</div>
                  <div className="text-white text-[10px] break-all">{currentAnalysis.sha256}</div>
                </div>
              </div>
            )}

            {/* Disassembly / Smali Tokens */}
            {activeTab === 'DISASSEMBLY' && (
              <pre className="p-4 rounded bg-[#000000] border border-[#222226] font-mono text-xs text-[#d4d4d8] overflow-x-auto leading-relaxed">
                {currentAnalysis.disassemblyStringsSample.join('\n')}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
