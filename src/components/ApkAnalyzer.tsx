import React, { useState } from 'react';
import { Smartphone, Shield, FileCode, AlertCircle } from 'lucide-react';

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
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight">
            Android Banking Trojan & Fake App Analysis Lab
          </h2>
          <p className="text-xs text-[#a1a1aa] mt-0.5">
            Static decompilation, dangerous SMS permissions, overlay attack detection, and C2 exfiltration extraction.
          </p>
        </div>

        {/* APK Selector */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-[#71717a] font-mono">Sample:</span>
          <select
            value={selectedApk.id}
            onChange={(e) => {
              const apk = SAMPLE_APKS.find(a => a.id === e.target.value);
              if (apk) setSelectedApk(apk);
            }}
            className="bg-[#121214] border border-[#27272a] text-xs rounded-md px-3 py-1.5 text-white focus:outline-none focus:border-white font-mono"
          >
            {SAMPLE_APKS.map(a => (
              <option key={a.id} value={a.id}>
                [{a.targetedBrand}] {a.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono">
        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Malware Risk Score</div>
          <div className="text-2xl font-bold text-white mt-1">{selectedApk.riskScore}%</div>
          <div className="text-[10px] text-[#a1a1aa] mt-0.5">CRITICAL TROJAN</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Targeted App</div>
          <div className="text-lg font-bold text-white mt-1">{selectedApk.targetedBrand}</div>
          <div className="text-[10px] text-[#71717a] truncate mt-0.5">{selectedApk.packageName}</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">Dangerous Perms</div>
          <div className="text-2xl font-bold text-white mt-1">{selectedApk.dangerousPermissions.length}</div>
          <div className="text-[10px] text-[#71717a] mt-0.5">SMS & Accessibility Abuse</div>
        </div>

        <div className="p-4 rounded-lg bg-[#09090b] border border-[#27272a]">
          <div className="text-[11px] uppercase text-[#71717a]">C2 Channels</div>
          <div className="text-2xl font-bold text-white mt-1">{selectedApk.c2Endpoints.length + 1}</div>
          <div className="text-[10px] text-[#71717a] mt-0.5">HTTPS Endpoint + Telegram</div>
        </div>
      </div>

      {/* Main Analysis View */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#27272a] pb-3">
          <div className="text-xs font-mono font-bold text-white uppercase">
            Static Forensics: {selectedApk.packageName}
          </div>

          <div className="flex items-center space-x-1 bg-[#121214] p-1 rounded-md border border-[#27272a] text-xs">
            <button
              onClick={() => setActiveTab('PERMISSIONS')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                activeTab === 'PERMISSIONS'
                  ? 'bg-white text-black font-semibold'
                  : 'text-[#a1a1aa] hover:text-white'
              }`}
            >
              Dangerous Permissions
            </button>
            <button
              onClick={() => setActiveTab('MANIFEST')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                activeTab === 'MANIFEST'
                  ? 'bg-white text-black font-semibold'
                  : 'text-[#a1a1aa] hover:text-white'
              }`}
            >
              AndroidManifest.xml
            </button>
            <button
              onClick={() => setActiveTab('C2_TELEMETRY')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                activeTab === 'C2_TELEMETRY'
                  ? 'bg-white text-black font-semibold'
                  : 'text-[#a1a1aa] hover:text-white'
              }`}
            >
              C2 Endpoints
            </button>
          </div>
        </div>

        {/* Tab 1: Permissions */}
        {activeTab === 'PERMISSIONS' && (
          <div className="space-y-3 font-mono">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {selectedApk.dangerousPermissions.map((perm) => (
                <div key={perm} className="p-3 rounded bg-[#121214] border border-[#27272a] text-xs space-y-1">
                  <div className="font-bold text-white break-all">{perm}</div>
                  <div className="text-[11px] text-[#a1a1aa]">
                    {perm.includes('RECEIVE_SMS') && 'Interception of 2FA Banking OTPs.'}
                    {perm.includes('BIND_ACCESSIBILITY_SERVICE') && 'Screen touch interception & auto-approval of UPI collect transfers.'}
                    {perm.includes('SYSTEM_ALERT_WINDOW') && 'Phishing overlays rendered over legitimate bank apps.'}
                    {perm.includes('READ_PHONE_STATE') && 'SIM IMSI/IMEI extraction for identity theft.'}
                    {perm.includes('REQUEST_INSTALL_PACKAGES') && 'Dropper payload for second-stage payloads.'}
                    {perm.includes('QUERY_ALL_PACKAGES') && 'Scans device for PhonePe, Paytm, or SBI apps.'}
                    {perm.includes('READ_CONTACTS') && 'Address book exfiltration for smishing spam.'}
                  </div>
                </div>
              ))}
            </div>

            <div className="p-3.5 rounded bg-[#000000] border border-[#27272a] space-y-1.5 text-xs">
              <div className="text-white font-bold uppercase text-[11px]">Malicious UPI Intent Hooks:</div>
              {selectedApk.intentFilters.map((intent, idx) => (
                <div key={idx} className="p-1.5 rounded bg-[#121214] border border-[#27272a] text-[#d4d4d8]">
                  {intent}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 2: AndroidManifest.xml */}
        {activeTab === 'MANIFEST' && (
          <pre className="p-4 rounded bg-[#000000] border border-[#27272a] font-mono text-xs text-[#d4d4d8] overflow-x-auto leading-relaxed">
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

        {/* Tab 3: C2 Telemetry */}
        {activeTab === 'C2_TELEMETRY' && (
          <div className="space-y-3 font-mono text-xs">
            <div className="p-3.5 rounded bg-[#000000] border border-[#27272a] space-y-2">
              <div className="text-white font-bold uppercase text-[11px]">Extracted C2 Gateways:</div>
              {selectedApk.c2Endpoints.map((ep, idx) => (
                <div key={idx} className="p-2 rounded bg-[#121214] border border-[#27272a] text-[#d4d4d8] break-all">
                  POST {ep}
                </div>
              ))}
            </div>

            {selectedApk.telegramBotHook && (
              <div className="p-3.5 rounded bg-[#000000] border border-[#27272a] space-y-2">
                <div className="text-white font-bold uppercase text-[11px]">Telegram Exfiltration Hook:</div>
                <div className="p-2 rounded bg-[#121214] border border-[#27272a] text-[#d4d4d8] break-all">
                  {selectedApk.telegramBotHook}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
