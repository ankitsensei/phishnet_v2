import React, { useState } from 'react';
import { Smartphone, ShieldAlert, FileCode, CheckCircle2, AlertTriangle, Terminal, Upload, Cpu, Download, Lock } from 'lucide-react';

interface ApkSample {
  id: string;
  name: string;
  packageName: string;
  sha256: string;
  targetedBrand: string;
  riskScore: number;
  dangerousPermissions: string[];
  intentFilters: string[];
  c2Endpoints: string[];
  telegramBotHook?: string;
  injectedPayload: string;
}

const SAMPLE_APKS: ApkSample[] = [
  {
    id: 'apk-1',
    name: 'SBI_Yono_Mandatory_Update_v4.2.apk',
    packageName: 'com.sbi.lotusapply.banking',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    targetedBrand: 'SBI YONO',
    riskScore: 99,
    dangerousPermissions: [
      'android.permission.RECEIVE_SMS',
      'android.permission.READ_SMS',
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.REQUEST_INSTALL_PACKAGES',
      'android.permission.QUERY_ALL_PACKAGES'
    ],
    intentFilters: [
      'android.intent.action.VIEW (scheme="upi", host="pay")',
      'android.provider.Telephony.SMS_RECEIVED'
    ],
    c2Endpoints: [
      'https://api.shadowvpa-c2.top/collect.php',
      'https://ru-gate-44.bulletproof.is/apk_sync'
    ],
    telegramBotHook: 'https://api.telegram.org/bot682910492:AAFe.../sendMessage?chat_id=-1002938102',
    injectedPayload: 'SMS Forwarder Daemon + Overlay Injection on top of genuine SBI YONO app'
  },
  {
    id: 'apk-2',
    name: 'PhonePe_Scratch_Reward_5000.apk',
    packageName: 'com.phonepe.rewards.instant',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    targetedBrand: 'PhonePe',
    riskScore: 96,
    dangerousPermissions: [
      'android.permission.READ_PHONE_STATE',
      'android.permission.RECEIVE_SMS',
      'android.permission.INTERNET',
      'android.permission.ACCESS_FINE_LOCATION'
    ],
    intentFilters: [
      'android.intent.action.MAIN',
      'android.intent.action.VIEW (scheme="phonepe")'
    ],
    c2Endpoints: [
      'https://phonepe-cashback-gate.xyz/log_user.php'
    ],
    telegramBotHook: 'https://api.telegram.org/bot718293019:AAGk.../sendMessage',
    injectedPayload: 'Simulated Scratch card that silently initiates UPI Collect request for ₹4,999'
  },
  {
    id: 'apk-3',
    name: 'Paytm_Fastag_KYC_Helper.apk',
    packageName: 'net.one97.paytm.kychelper',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    targetedBrand: 'Paytm',
    riskScore: 94,
    dangerousPermissions: [
      'android.permission.READ_CONTACTS',
      'android.permission.READ_SMS',
      'android.permission.RECEIVE_BOOT_COMPLETED',
      'android.permission.CAMERA'
    ],
    intentFilters: [
      'android.intent.action.VIEW (scheme="upi")'
    ],
    c2Endpoints: [
      'https://fastag-help-alavisa.in/kyc_dump'
    ],
    injectedPayload: 'Phishing login screen with automatic OTP interception service running in background'
  }
];

export const ApkAnalyzer: React.FC = () => {
  const [selectedApk, setSelectedApk] = useState<ApkSample>(SAMPLE_APKS[0]);
  const [activeTab, setActiveTab] = useState<'PERMISSIONS' | 'MANIFEST' | 'C2_TELEMETRY'>('PERMISSIONS');

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="p-4 rounded-xl bg-[#0c1017] border border-white/10 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Smartphone className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white font-display flex items-center space-x-2">
              <span>Android Banking Trojan & Fake App Static Analysis</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                APK Manifest • UPI Intent Interceptors
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Decompilation, dangerous SMS permissions, overlay attack detection and C2 extraction
            </p>
          </div>
        </div>

        {/* APK Selector */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Select Malware Sample:</span>
          <select
            value={selectedApk.id}
            onChange={(e) => {
              const apk = SAMPLE_APKS.find(a => a.id === e.target.value);
              if (apk) setSelectedApk(apk);
            }}
            className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {SAMPLE_APKS.map(a => (
              <option key={a.id} value={a.id}>
                [{a.targetedBrand}] {a.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Overview Details Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0d121c] border border-rose-500/30">
          <div className="text-[11px] uppercase font-mono text-slate-400">Malware Threat Level</div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{selectedApk.riskScore} / 100</div>
          <div className="text-[10px] text-rose-300 font-mono mt-0.5">CRITICAL BANKING TROJAN</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d121c] border border-white/10">
          <div className="text-[11px] uppercase font-mono text-slate-400">Targeted Entity</div>
          <div className="text-lg font-bold text-white mt-1">{selectedApk.targetedBrand}</div>
          <div className="text-[10px] text-cyan-400 font-mono mt-0.5">{selectedApk.packageName}</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d121c] border border-white/10">
          <div className="text-[11px] uppercase font-mono text-slate-400">Dangerous Permissions</div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{selectedApk.dangerousPermissions.length}</div>
          <div className="text-[10px] text-slate-400 font-mono mt-0.5">SMS & Accessibility Abuse</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d121c] border border-white/10">
          <div className="text-[11px] uppercase font-mono text-slate-400">C2 Channels</div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-1">{selectedApk.c2Endpoints.length + 1}</div>
          <div className="text-[10px] text-slate-400 font-mono mt-0.5">HTTPS API + Telegram Bot</div>
        </div>
      </div>

      {/* Main Analysis Tabs */}
      <div className="p-5 rounded-xl bg-[#0b0f17] border border-white/10 space-y-4 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold text-white uppercase">
              Static Forensics & Smali Decompile
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              SHA256: {selectedApk.sha256.slice(0, 16)}...
            </span>
          </div>

          <div className="flex items-center space-x-2 bg-[#121824] p-1 rounded-lg border border-white/10 text-xs">
            <button
              onClick={() => setActiveTab('PERMISSIONS')}
              className={`px-3 py-1 rounded font-medium transition-all ${
                activeTab === 'PERMISSIONS'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Dangerous Permissions
            </button>
            <button
              onClick={() => setActiveTab('MANIFEST')}
              className={`px-3 py-1 rounded font-medium transition-all ${
                activeTab === 'MANIFEST'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              AndroidManifest.xml
            </button>
            <button
              onClick={() => setActiveTab('C2_TELEMETRY')}
              className={`px-3 py-1 rounded font-medium transition-all ${
                activeTab === 'C2_TELEMETRY'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              C2 & Telegram Endpoints
            </button>
          </div>
        </div>

        {/* Tab 1: Permissions */}
        {activeTab === 'PERMISSIONS' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {selectedApk.dangerousPermissions.map((perm) => (
                <div
                  key={perm}
                  className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/30 flex items-start space-x-3 text-xs"
                >
                  <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="font-mono font-bold text-rose-300 break-all">{perm}</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      {perm.includes('RECEIVE_SMS') && 'Enables background interception of 2FA Bank OTPs.'}
                      {perm.includes('BIND_ACCESSIBILITY_SERVICE') && 'Used to hijack screen touches and auto-approve UPI Collect transfers.'}
                      {perm.includes('SYSTEM_ALERT_WINDOW') && 'Draws fake phishing overlays on top of genuine banking applications.'}
                      {perm.includes('READ_PHONE_STATE') && 'Extracts SIM IMSI/IMEI for mobile number identity spoofing.'}
                      {perm.includes('REQUEST_INSTALL_PACKAGES') && 'Acts as a dropper to download second-stage malware payloads.'}
                      {perm.includes('QUERY_ALL_PACKAGES') && 'Scans device to check if PhonePe, Paytm, or SBI YONO is installed.'}
                      {perm.includes('READ_CONTACTS') && 'Exfiltrates victim address book to spam smishing SMS lures.'}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="p-3.5 rounded-lg bg-[#090d14] border border-white/5 space-y-2">
              <div className="text-xs font-mono font-bold text-cyan-400 uppercase">Malicious UPI Intent Handlers:</div>
              {selectedApk.intentFilters.map((intent, idx) => (
                <div key={idx} className="p-2 rounded bg-cyan-950/20 border border-cyan-500/30 font-mono text-xs text-cyan-300">
                  {intent}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 2: AndroidManifest.xml */}
        {activeTab === 'MANIFEST' && (
          <pre className="p-4 rounded-lg bg-[#06090e] border border-white/10 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
{`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${selectedApk.packageName}"
    android:versionCode="42"
    android:versionName="4.2.0">

    ${selectedApk.dangerousPermissions.map(p => `<uses-permission android:name="${p}" />`).join('\n    ')}

    <application
        android:allowBackup="false"
        android:icon="@mipmap/ic_launcher"
        android:label="${selectedApk.targetedBrand} Official Update"
        android:theme="@style/AppTheme">

        <service
            android:name=".services.SmsStealerService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
        </service>

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            ${selectedApk.intentFilters.map(i => `<!-- Hijack Intent: ${i} -->`).join('\n            ')}
        </activity>
    </application>
</manifest>`}
          </pre>
        )}

        {/* Tab 3: C2 Endpoints */}
        {activeTab === 'C2_TELEMETRY' && (
          <div className="space-y-3 font-mono text-xs">
            <div className="p-3.5 rounded-lg bg-[#090d14] border border-white/5 space-y-2">
              <div className="text-rose-400 font-bold uppercase">Extracted Exfiltration Endpoints:</div>
              {selectedApk.c2Endpoints.map((ep, idx) => (
                <div key={idx} className="p-2 rounded bg-rose-950/20 border border-rose-500/30 text-rose-300 break-all">
                  POST {ep}
                </div>
              ))}
            </div>

            {selectedApk.telegramBotHook && (
              <div className="p-3.5 rounded-lg bg-[#090d14] border border-white/5 space-y-2">
                <div className="text-cyan-400 font-bold uppercase">Direct Telegram Exfiltration Bot Hook:</div>
                <div className="p-2 rounded bg-cyan-950/20 border border-cyan-500/30 text-cyan-300 break-all">
                  {selectedApk.telegramBotHook}
                </div>
              </div>
            )}

            <div className="p-3.5 rounded-lg bg-[#090d14] border border-white/5">
              <div className="text-amber-400 font-bold uppercase mb-1">Payload Analysis:</div>
              <div className="text-slate-300 text-xs">{selectedApk.injectedPayload}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
