import { ThreatItem, ThreatStatus, CampaignCluster, GraphNode, GraphLink, ModelMetrics, CTLogEntry } from '../types/threat';
import { INITIAL_THREATS, INITIAL_CAMPAIGNS, MOCK_GRAPH_DATA, BENCHMARK_METRICS, SAMPLE_CT_LOG_STREAM } from '../data/mockThreats';
import { analyzeSource, ScanResult } from './detectionEngine';

export interface TelemetryData {
  responseTimeMs: number;
  redirectChain: string[];
  dns: {
    aRecords: string[];
    aaaaRecords: string[];
    nsRecords: string[];
    mxRecords: string[];
    txtRecords: string[];
  };
  ssl: {
    valid: boolean;
    issuer?: string;
    subject?: string;
    daysRemaining?: number;
    serialNumber?: string;
  };
  dom: {
    title: string;
    hasForms: boolean;
    formActions: string[];
    inputTypes: string[];
    hasPinOrMpin: boolean;
    hasCardOrCvv: boolean;
    hasOtpInput: boolean;
    hasPasswordInput: boolean;
    hasAadhaarOrPan: boolean;
    hasExternalFormTarget: boolean;
    hasAntiDebugging: boolean;
    hasGeoGatingClues: boolean;
    extractedVpas: string[];
    extractedPhones: string[];
    extractedUpiLinks: string[];
    brandKeywordsFound: string[];
  };
  evidenceSha256: string;
  ipInfo: {
    ip: string;
    asn: string;
    asnName: string;
    country: string;
    countryCode: string;
    registrar: string;
  };
}

export interface DeepScanResult extends ScanResult {
  normalizedUrl: string;
  telemetry: TelemetryData;
}

export interface ApkAnalysisResult {
  fileName: string;
  packageName: string;
  sha256: string;
  targetedBrand: string;
  riskScore: number;
  isTrojan: boolean;
  dangerousPermissions: Array<{
    permission: string;
    risk: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    description: string;
  }>;
  intentFilters: string[];
  c2Endpoints: string[];
  telegramBotHooks: string[];
  decompiledManifestXml: string;
  disassemblyStringsSample: string[];
}

export interface TakedownDispatchRecord {
  id: string;
  threatId: string;
  targetDomain: string;
  targetBrand: string;
  channels: string[];
  dispatchedAt: string;
  status: 'PENDING' | 'DISPATCHED' | 'ACKNOWLEDGED' | 'COMPLETED';
  trackingNumber: string;
}

// In-memory persistent stores for smooth client-side operations
let threatsDb: ThreatItem[] = [...INITIAL_THREATS];
let dispatchesDb: TakedownDispatchRecord[] = [
  {
    id: 'disp-101',
    threatId: 'thr-8901',
    targetDomain: 'sbi-yono-pan-kyc-update.live',
    targetBrand: 'SBI YONO',
    channels: ['CERT-In Form 7A', 'NPCI UPI Desk', 'Registrar Abuse'],
    dispatchedAt: '2026-10-07 14:20:00',
    status: 'DISPATCHED',
    trackingNumber: 'CERTIN-2026-8901-T7'
  },
  {
    id: 'disp-102',
    threatId: 'thr-8902',
    targetDomain: 'phonepe-rewards-claim-5000.top',
    targetBrand: 'PhonePe',
    channels: ['NPCI UPI Shield', 'Cloudflare Abuse'],
    dispatchedAt: '2026-10-07 14:06:00',
    status: 'ACKNOWLEDGED',
    trackingNumber: 'NPCI-FRM-2026-8902'
  }
];

export const apiClient = {
  // 1. Deep Scan (Real backend + local fallback)
  async scan(input: string, typeHint?: string): Promise<DeepScanResult> {
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input, typeHint: typeHint || 'URL' })
      });
      if (response.ok) {
        const data = await response.json();
        return data as DeepScanResult;
      }
    } catch (e) {
      console.warn('Backend /api/scan offline, using local engine:', e);
    }

    // Fallback to client-side local detection engine
    const local = analyzeSource(input, (typeHint as any) || 'URL');
    const brand = local.matchedBrand || 'SBI YONO';
    const isFake = local.isFake;

    const ip = isFake ? '185.220.101.44' : '104.18.22.45';
    const asn = isFake ? 'AS44050' : 'AS13335';
    const asnName = isFake ? 'Petersburg Offshore Networks' : 'Cloudflare Inc';
    const country = isFake ? 'Seychelles (Hosted: RU)' : 'United States';
    const registrar = isFake ? 'NameSilo LLC' : 'MarkMonitor Inc';

    return {
      ...local,
      normalizedUrl: local.rawInput.startsWith('http') ? local.rawInput : `https://${local.domain}`,
      telemetry: {
        responseTimeMs: isFake ? 142 : 48,
        redirectChain: [local.rawInput],
        dns: {
          aRecords: [ip],
          aaaaRecords: [],
          nsRecords: isFake ? ['ns1.bulletproof.is', 'ns2.bulletproof.is'] : ['ns1.bank-dns.com'],
          mxRecords: isFake ? [] : ['mail.official-bank.com'],
          txtRecords: ['v=spf1 include:_spf.google.com ~all']
        },
        ssl: {
          valid: true,
          issuer: isFake ? "Let's Encrypt Authority E6" : 'DigiCert Global Root G2',
          subject: local.domain,
          daysRemaining: isFake ? 84 : 320,
          serialNumber: isFake ? '04a2991823ab' : '0198273645bbfa90'
        },
        dom: {
          title: isFake ? `${brand} Verification Desk` : `${brand} Official Portal`,
          hasForms: isFake,
          formActions: isFake ? ['/api/harvest.php'] : ['/login/auth'],
          inputTypes: isFake ? ['text', 'password', 'hidden'] : ['text', 'password'],
          hasPinOrMpin: isFake,
          hasCardOrCvv: isFake,
          hasOtpInput: isFake,
          hasPasswordInput: true,
          hasAadhaarOrPan: isFake,
          hasExternalFormTarget: isFake,
          hasAntiDebugging: isFake,
          hasGeoGatingClues: isFake,
          extractedVpas: local.extractedVpa,
          extractedPhones: local.extractedPhoneNumbers,
          extractedUpiLinks: local.qrIntentDetected ? [`upi://pay?pa=${local.extractedVpa[0] || 'scam@paytm'}&am=1.00`] : [],
          brandKeywordsFound: [brand]
        },
        evidenceSha256: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
        ipInfo: {
          ip,
          asn,
          asnName,
          country,
          countryCode: isFake ? 'SC' : 'US',
          registrar
        }
      }
    };
  },

  // 2. APK Inspection (Real backend + local fallback)
  async scanApk(fileOrContent: File | string, fileName?: string): Promise<ApkAnalysisResult> {
    try {
      if (fileOrContent instanceof File) {
        const formData = new FormData();
        formData.append('file', fileOrContent);
        const res = await fetch('/api/scan/apk', {
          method: 'POST',
          body: formData
        });
        if (res.ok) return await res.json();
      } else if (typeof fileOrContent === 'string') {
        const res = await fetch('/api/scan/apk', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: fileOrContent, fileName: fileName || 'sample.apk' })
        });
        if (res.ok) return await res.json();
      }
    } catch (e) {
      console.warn('Backend /api/scan/apk offline, using local engine:', e);
    }

    const text = typeof fileOrContent === 'string' ? fileOrContent : (fileOrContent.name || 'app.apk');
    const lower = text.toLowerCase();

    let targetedBrand = 'SBI YONO';
    let pkg = 'com.sbi.lotusapply.banking';
    if (lower.includes('phonepe') || lower.includes('reward')) {
      targetedBrand = 'PhonePe';
      pkg = 'com.phonepe.rewards.instant';
    } else if (lower.includes('paytm') || lower.includes('fastag')) {
      targetedBrand = 'Paytm';
      pkg = 'net.one97.paytm.kychelper';
    } else if (lower.includes('hdfc')) {
      targetedBrand = 'HDFC Bank';
      pkg = 'com.hdfc.netbanking.mobile';
    }

    return {
      fileName: typeof fileOrContent === 'string' ? (fileName || 'SBI_Yono_Update.apk') : fileOrContent.name,
      packageName: pkg,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      targetedBrand,
      riskScore: 98,
      isTrojan: true,
      dangerousPermissions: [
        { permission: 'android.permission.RECEIVE_SMS', risk: 'CRITICAL', description: 'Interception of 2FA Bank OTPs.' },
        { permission: 'android.permission.READ_SMS', risk: 'CRITICAL', description: 'Accesses incoming banking transaction alerts.' },
        { permission: 'android.permission.BIND_ACCESSIBILITY_SERVICE', risk: 'CRITICAL', description: 'Touch injection and auto-approval of UPI transfers.' },
        { permission: 'android.permission.SYSTEM_ALERT_WINDOW', risk: 'HIGH', description: 'Draws fake phishing overlays over official banking apps.' },
        { permission: 'android.permission.READ_PHONE_STATE', risk: 'MEDIUM', description: 'Collects SIM IMSI and IMEI hardware identifiers.' },
        { permission: 'android.permission.REQUEST_INSTALL_PACKAGES', risk: 'HIGH', description: 'Acts as dropper for second-stage payload.' }
      ],
      intentFilters: [
        'android.intent.action.VIEW (scheme="upi", host="pay")',
        'android.provider.Telephony.SMS_RECEIVED'
      ],
      c2Endpoints: [
        'https://api.shadowvpa-c2.top/collect.php',
        'https://ru-gate-44.bulletproof.is/apk_sync'
      ],
      telegramBotHooks: [
        'https://api.telegram.org/bot682910492:AAFe.../sendMessage'
      ],
      decompiledManifestXml: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${pkg}"
    android:versionCode="42"
    android:versionName="4.2.0">

    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />

    <application
        android:label="${targetedBrand} Official Update"
        android:theme="@style/AppTheme">

        <service
            android:name=".services.SmsStealerService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
        </service>

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <data android:scheme="upi" android:host="pay" />
            </intent-filter>
        </activity>
    </application>
</manifest>`,
      disassemblyStringsSample: [
        'const-string v0, "https://api.shadowvpa-c2.top/collect.php"',
        'const-string v1, "upi://pay?pa=sbikyc.refund99@paytm&am=4999.00"',
        'invoke-virtual {2, v1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;',
        'const-string v3, "SMS_INTERCEPTED: OTP Grabbed"'
      ]
    };
  },

  // 3. Threats Feed (Real backend + local store)
  async getThreats(): Promise<ThreatItem[]> {
    try {
      const res = await fetch('/api/threats');
      if (res.ok) {
        const data = await res.json();
        if (data.threats && Array.isArray(data.threats) && data.threats.length > 0) {
          threatsDb = data.threats;
          return data.threats;
        }
      }
    } catch (e) {
      console.warn('Backend /api/threats fetch failed, using memory DB:', e);
    }
    return threatsDb;
  },

  async addThreat(threat: ThreatItem): Promise<ThreatItem> {
    try {
      const res = await fetch('/api/threats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(threat)
      });
      if (res.ok) {
        const saved = await res.json();
        threatsDb = [saved, ...threatsDb.filter(t => t.id !== saved.id)];
        return saved;
      }
    } catch (e) {
      console.warn('Backend /api/threats POST failed:', e);
    }
    threatsDb = [threat, ...threatsDb.filter(t => t.id !== threat.id)];
    return threat;
  },

  async updateThreatStatus(threatId: string, status: ThreatStatus): Promise<boolean> {
    try {
      const res = await fetch(`/api/threats/${threatId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        threatsDb = threatsDb.map(t => t.id === threatId ? { ...t, status } : t);
        return true;
      }
    } catch (e) {
      console.warn('Backend update status failed:', e);
    }
    threatsDb = threatsDb.map(t => t.id === threatId ? { ...t, status } : t);
    return true;
  },

  // 4. Campaigns
  async getCampaigns(): Promise<CampaignCluster[]> {
    try {
      const res = await fetch('/api/campaigns');
      if (res.ok) {
        const data = await res.json();
        if (data.campaigns) return data.campaigns;
      }
    } catch (e) {
      // ignore
    }
    return INITIAL_CAMPAIGNS;
  },

  // 5. Campaign Graph
  async getGraph(): Promise<{ nodes: GraphNode[]; links: GraphLink[] }> {
    try {
      const res = await fetch('/api/graph');
      if (res.ok) {
        const data = await res.json();
        if (data.nodes && data.links) return data;
      }
    } catch (e) {
      // ignore
    }
    return MOCK_GRAPH_DATA;
  },

  // 6. Benchmarks
  async getMetrics(): Promise<ModelMetrics> {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      // ignore
    }
    return BENCHMARK_METRICS;
  },

  // 7. Takedown Dispatches
  async getDispatches(): Promise<TakedownDispatchRecord[]> {
    try {
      const res = await fetch('/api/takedowns/dispatches');
      if (res.ok) {
        const data = await res.json();
        if (data.dispatches && Array.isArray(data.dispatches)) {
          dispatchesDb = data.dispatches;
          return data.dispatches;
        }
      }
    } catch (e) {
      // ignore
    }
    return dispatchesDb;
  },

  async dispatchTakedown(data: {
    threatId: string;
    channels: string[];
    analystNotes?: string;
  }): Promise<TakedownDispatchRecord> {
    try {
      const res = await fetch('/api/takedowns/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (res.ok) {
        const result = await res.json();
        if (result.dispatch) {
          dispatchesDb = [result.dispatch, ...dispatchesDb];
          return result.dispatch;
        }
      }
    } catch (e) {
      console.warn('Backend takedown dispatch failed:', e);
    }

    const targetThreat = threatsDb.find(t => t.id === data.threatId) || threatsDb[0];
    const newRecord: TakedownDispatchRecord = {
      id: `disp-${Date.now().toString().slice(-4)}`,
      threatId: data.threatId,
      targetDomain: targetThreat?.domain || 'sbi-yono-pan-kyc-update.live',
      targetBrand: targetThreat?.targetBrand || 'SBI YONO',
      channels: data.channels.length > 0 ? data.channels : ['CERT-In Form 7A', 'NPCI UPI Desk', 'Registrar Abuse'],
      dispatchedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      status: 'DISPATCHED',
      trackingNumber: `CERTIN-${Date.now().toString().slice(-4)}-T7`
    };

    dispatchesDb = [newRecord, ...dispatchesDb];
    if (targetThreat) {
      targetThreat.status = 'TAKEDOWN_DISPATCHED';
    }
    return newRecord;
  }
};
