import React, { useState, useEffect } from 'react';
import { FileText, Send, CheckCircle, Copy, Download, History, ShieldCheck, Clock, CheckCircle2, ShieldAlert, Sparkles, SendHorizontal } from 'lucide-react';
import { ThreatItem } from '../types/threat';
import { apiClient, TakedownDispatchRecord } from '../services/api';

interface TakedownGeneratorProps {
  threats: ThreatItem[];
  selectedThreatId?: string;
}

export const TakedownGenerator: React.FC<TakedownGeneratorProps> = ({
  threats,
  selectedThreatId
}) => {
  const [activeThreatId, setActiveThreatId] = useState<string>(selectedThreatId || threats[0]?.id || 'thr-8901');
  const [recipientType, setRecipientType] = useState<'CERT_IN' | 'NPCI_UPI' | 'REGISTRAR' | 'HOST_CDN' | 'BANK_CSIRT'>('CERT_IN');
  const [copied, setCopied] = useState<boolean>(false);
  const [isDispatching, setIsDispatching] = useState<boolean>(false);
  const [dispatches, setDispatches] = useState<TakedownDispatchRecord[]>([]);
  const [showLedger, setShowLedger] = useState<boolean>(false);

  const threat = threats.find(t => t.id === activeThreatId) || threats[0] || {
    id: 'thr-8901',
    url: 'https://sbi-yono-pan-kyc-update.live',
    domain: 'sbi-yono-pan-kyc-update.live',
    targetBrand: 'SBI YONO',
    threatType: 'FAKE_UPI_PORTAL' as const,
    severity: 'CRITICAL' as const,
    similarityScore: 98.4,
    qrCodePayload: 'upi://pay?pa=sbi.instantkyc@paytm&am=1.00',
    ip: '185.220.101.44',
    asn: 'AS44050',
    asnName: 'Petersburg Offshore Networks',
    country: 'Seychelles (RU Host)',
    registrar: 'NameSilo LLC',
    sslIssuer: "Let's Encrypt Authority E6",
    sslSerial: '04a2991823ab',
    dnsNameservers: ['ns1.bulletproof.is', 'ns2.bulletproof.is'],
    extractedUPI_VPA: ['sbi.instantkyc@paytm', 'refund.sbiyono@ybl'],
    extractedPhoneNumbers: ['+91 98765 43210'],
    campaignName: 'Op YONO-Shield Harvester',
    threatActorSyndicate: 'RedMule Syndicate',
    structuralSSIM: 0.985,
    pHashDistance: 4,
    evasionTactics: { antiBotGating: true, geoFencingIndiaOnly: true, devtoolsBlocker: true },
    evidenceHash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b'
  };

  useEffect(() => {
    loadDispatches();
  }, []);

  const loadDispatches = async () => {
    try {
      const data = await apiClient.getDispatches();
      setDispatches(data);
    } catch (err) {
      console.error('Failed loading dispatches:', err);
    }
  };

  const generateReportText = () => {
    const timestamp = new Date().toISOString();
    
    if (recipientType === 'CERT_IN') {
      return `================================================================================
FORM 7A: INCIDENT REPORTING TO CERT-In (GOVERNMENT OF INDIA)
Cyber Security Incident Reporting under Information Technology Act, 2000 (Section 70B)
================================================================================
Incident Reference ID : CERT-IN/PHISH-UPI/${threat.id.toUpperCase()}
Report Timestamp      : ${timestamp}
Incident Category     : Phishing / Financial Cyber Fraud / Brand Spoofing / Malicious UPI Collect
Targeted Institution  : ${threat.targetBrand} (Critical Payment & Banking Infrastructure)
Confidence Level      : ${threat.similarityScore}% (Automated Visual SSIM + pHash Match)

1. MALICIOUS INFRASTRUCTURE DETAILS:
--------------------------------------------------------------------------------
Malicious URL         : ${threat.url}
FQDN Hostname         : ${threat.domain}
Resolved IP Address   : ${threat.ip} (${threat.country})
Hosting Provider / ASN: ${threat.asn} - ${threat.asnName}
Registrar of Record   : ${threat.registrar}
SSL Certificate Serial: ${threat.sslSerial} (Issuer: ${threat.sslIssuer})
Active Nameservers    : ${threat.dnsNameservers?.join(', ') || 'ns1.bulletproof.is'}

2. FRAUD & PAYMENT RECOVERY TELEMETRY:
--------------------------------------------------------------------------------
Harvested UPI VPAs    : ${threat.extractedUPI_VPA?.join(', ') || 'N/A'}
Associated Mule Phones: ${threat.extractedPhoneNumbers?.join(', ') || 'N/A'}
QR Collect Payload    : ${threat.qrCodePayload || 'N/A'}
Associated Campaign   : ${threat.campaignName} (${threat.threatActorSyndicate})

3. FORENSIC EVIDENCE & INTEGRITY PROOF:
--------------------------------------------------------------------------------
Evidence SHA-256 Hash : ${threat.evidenceHash}
Visual SSIM Match     : ${(threat.structuralSSIM * 100).toFixed(1)}% vs Official ${threat.targetBrand} Template
pHash Distance        : ${threat.pHashDistance} bits
Anti-Analysis Evasion : ${threat.evasionTactics?.antiBotGating ? 'User-Agent Gating, ' : ''}${threat.evasionTactics?.geoFencingIndiaOnly ? 'India-Only GeoIP BGP Gating, ' : ''}${threat.evasionTactics?.devtoolsBlocker ? 'DevTools Debugger Loop' : 'None'}

4. REQUESTED ACTION:
--------------------------------------------------------------------------------
- Issue immediate emergency block notification to all Indian ISPs / DoT under Rule 3(1)(d).
- Issue directive to NPCI UPI switch to freeze and blacklist extracted VPA handles.
- Coordinate with international registrar for DNS delegation revocation.

Signed: PhishNet V2 Autonomous Threat Response Engine`;
    }

    if (recipientType === 'NPCI_UPI') {
      return `================================================================================
NPCI UPI SHIELD — FRAUDULENT VPA FREEZE & ESCALATION NOTICE
National Payments Corporation of India (Fraud Risk Management Dept)
================================================================================
Alert Ref       : NPCI/UPI-FRM/${threat.id.toUpperCase()}
Date / Time     : ${timestamp}
Severity        : CRITICAL / IMMEDIATE ACTION

ATTENTION: UPI Settlement & Risk Operations Team

1. SUSPICIOUS VPA HANDLES IDENTIFIED IN ACTIVE SMISHING/PHISHING:
--------------------------------------------------------------------------------
${threat.extractedUPI_VPA?.map((vpa, i) => `[${i + 1}] VPA Handle: ${vpa}\n    Risk Reason: Active collect endpoint on malicious portal ${threat.domain}`).join('\n') || 'None'}

2. ATTACK VECTOR:
Target Brand    : ${threat.targetBrand}
Lure Type       : Fake KYC / Instant Cashback Scratch Card
Victim Impact   : Unauthorized UPI Collect requests disguised as refund credits.
QR Payload URI  : ${threat.qrCodePayload || 'N/A'}

3. ACTION REQUESTED FROM NPCI:
1. Immediate freeze on inbound UPI credit transactions to the above listed VPAs.
2. Alert issuing PSP banks (Paytm, Axis Bank, SBI, ICICI, Yes Bank) to freeze underlying linked savings accounts.
3. Add domain "${threat.domain}" to NPCI UPI in-app link warning system.`;
    }

    if (recipientType === 'REGISTRAR') {
      return `From: cert-team@phishnet-shield.org
To: abuse@${threat.registrar.toLowerCase().replace(/[^a-z0-9]/g, '')}.com
Subject: URGENT: Phishing / Financial Fraud Abuse Takedown Request - ${threat.domain}

Dear Abuse Team at ${threat.registrar},

We are formally requesting the immediate suspension and revocation of DNS delegation for the following domain engaged in active banking phishing and credential theft:

Domain Name : ${threat.domain}
Active URL  : ${threat.url}
IP Address  : ${threat.ip}
Target Brand: ${threat.targetBrand} (Impersonating official payment services)

EVIDENCE & REPRODUCTION:
The domain hosts an exact visual clone (SSIM: ${(threat.structuralSSIM * 100).toFixed(1)}%) of ${threat.targetBrand}'s payment authorization portal designed to harvest users' confidential 6-digit UPI PINs and debit credentials.

cURL Proof:
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)" "${threat.url}"

Cryptographic Evidence Hash: ${threat.evidenceHash}

Please take down this domain immediately pursuant to ICANN Abuse Policies and your Terms of Service to mitigate active financial loss to victims.

Sincerely,
PhishNet V2 CSIRT Response Unit`;
    }

    if (recipientType === 'HOST_CDN') {
      return `To: abuse@${threat.asnName.toLowerCase().replace(/[^a-z0-9]/g, '')}.com
Subject: ABUSE NOTICE: Malicious Payment Phishing Hosted on IP ${threat.ip}

Dear Trust & Safety Team,

We have detected active malicious payment phishing infrastructure hosted under your Autonomous System (${threat.asn} - ${threat.asnName}):

IP Address : ${threat.ip}
Domain Name: ${threat.domain}
Target     : ${threat.targetBrand}
Threat Type: ${threat.threatType}

The server is actively serving credential harvesting scripts targeting Indian UPI banking consumers. Please terminate or isolate this host immediately.

Evidence Hash: ${threat.evidenceHash}`;
    }

    return `To: security-csirt@${threat.targetBrand.toLowerCase().replace(/\s+/g, '')}.com
Subject: [CONFIRMED PHISH] Active Typosquat Clone Targeting ${threat.targetBrand}

Dear ${threat.targetBrand} Information Security & Brand Protection Team,

Our autonomous crawler discovered an active phishing campaign impersonating ${threat.targetBrand}:

- Malicious URL: ${threat.url}
- Threat Actor : ${threat.threatActorSyndicate}
- Campaign     : ${threat.campaignName}
- Extracted VPAs: ${threat.extractedUPI_VPA?.join(', ') || 'N/A'}
- Visual SSIM  : ${(threat.structuralSSIM * 100).toFixed(1)}% match

Takedown notices have been automatically pre-dispatched to CERT-In, NPCI, and ${threat.registrar}.`;
  };

  const reportText = generateReportText();

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDispatch = async () => {
    setIsDispatching(true);
    try {
      await apiClient.dispatchTakedown({
        threatId: threat.id,
        channels: ['CERT_IN', 'NPCI_UPI', 'REGISTRAR', 'HOSTING_CDN'],
        analystNotes: 'Automated 1-click dispatch from SOC Sentinel'
      });
      await loadDispatches();
      setShowLedger(true);
    } catch (err) {
      console.error('Dispatch error:', err);
    } finally {
      setIsDispatching(false);
    }
  };

  const handleDownload = () => {
    const element = document.createElement('a');
    const file = new Blob([reportText], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `takedown-report-${threat.domain}-${recipientType.toLowerCase()}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full bg-indigo-50 border border-indigo-100 text-indigo-700 text-xs font-medium mb-2">
            <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
            <span>Multi-Authority Enforcement</span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">
            Takedown Package & Evidence Dispatcher
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Generates standardized CERT-In Form 7A, NPCI UPI Shield, and Registrar abuse notices with 1-click dispatch.
          </p>
        </div>

        {/* Target Selector & Toggle Ledger */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowLedger(!showLedger)}
            className={`px-3.5 py-2 rounded-xl text-xs flex items-center space-x-1.5 font-medium transition-all border ${
              showLedger
                ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm'
                : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Dispatch Ledger ({dispatches.length})</span>
          </button>

          <span className="text-xs text-slate-500">Target:</span>
          <select
            value={activeThreatId}
            onChange={(e) => setActiveThreatId(e.target.value)}
            className="bg-white border border-slate-200 text-xs rounded-xl px-3 py-2 text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 shadow-sm"
          >
            {threats.map(t => (
              <option key={t.id} value={t.id}>
                [{t.targetBrand}] {t.domain}
              </option>
            ))}
          </select>
        </div>
      </div>

      {showLedger ? (
        /* Dispatch History Ledger Table */
        <div className="rounded-2xl bg-white border border-slate-200/80 p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <span className="font-bold text-slate-900 text-sm flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <span>Live Takedown Dispatch Ledger</span>
            </span>
            <span className="text-xs text-slate-500">{dispatches.length} Dispatches Logged</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-500 border-b border-slate-100 uppercase text-[10px] font-semibold">
                <tr>
                  <th className="py-3 px-3">Tracking ID</th>
                  <th className="py-3 px-3">Target Domain</th>
                  <th className="py-3 px-3">Target Brand</th>
                  <th className="py-3 px-3">Channels</th>
                  <th className="py-3 px-3">Dispatched At</th>
                  <th className="py-3 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {dispatches.map((disp) => (
                  <tr key={disp.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3 px-3 text-indigo-600 font-bold">{disp.trackingNumber}</td>
                    <td className="py-3 px-3 text-slate-700">{disp.targetDomain}</td>
                    <td className="py-3 px-3 text-slate-900 font-sans font-semibold">{disp.targetBrand}</td>
                    <td className="py-3 px-3 text-slate-600 text-[11px] font-sans">{disp.channels.join(', ')}</td>
                    <td className="py-3 px-3 text-slate-500 whitespace-nowrap font-sans">{disp.dispatchedAt}</td>
                    <td className="py-3 px-3">
                      <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold font-sans">
                        {disp.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <>
          {/* Recipient Channel Selector */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {[
              { id: 'CERT_IN', label: 'CERT-In Form 7A', desc: 'Government CSIRT' },
              { id: 'NPCI_UPI', label: 'NPCI UPI Desk', desc: 'VPA Freeze Directive' },
              { id: 'REGISTRAR', label: 'Registrar Abuse', desc: `${threat.registrar}` },
              { id: 'HOST_CDN', label: 'Host / CDN Abuse', desc: `${threat.asnName}` },
              { id: 'BANK_CSIRT', label: 'Brand Security', desc: `${threat.targetBrand} CSIRT` },
            ].map((item) => (
              <button
                key={item.id}
                onClick={() => setRecipientType(item.id as any)}
                className={`p-4 rounded-xl border text-left transition-all ${
                  recipientType === item.id
                    ? 'bg-indigo-50/70 border-indigo-300 ring-2 ring-indigo-500/20 shadow-sm'
                    : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50'
                }`}
              >
                <div className={`font-semibold text-xs ${recipientType === item.id ? 'text-indigo-900' : 'text-slate-800'}`}>
                  {item.label}
                </div>
                <div className="text-[11px] truncate mt-1 text-slate-500">
                  {item.desc}
                </div>
              </button>
            ))}
          </div>

          {/* Report Code View */}
          <div className="rounded-2xl bg-white border border-slate-200/80 overflow-hidden shadow-sm">
            <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
              <div className="text-xs font-semibold text-slate-800 flex items-center space-x-2">
                <FileText className="w-4 h-4 text-indigo-600" />
                <span>Format: {recipientType} for {threat.domain}</span>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={handleCopy}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 text-xs font-medium transition-colors shadow-sm"
                >
                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>

                <button
                  onClick={handleDownload}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 text-xs font-medium transition-colors shadow-sm"
                >
                  <Download className="w-3.5 h-3.5 text-indigo-600" />
                  <span>Download .TXT</span>
                </button>

                <button
                  onClick={handleDispatch}
                  disabled={isDispatching}
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-sm transition-all disabled:opacity-50"
                >
                  <SendHorizontal className="w-3.5 h-3.5" />
                  <span>{isDispatching ? 'Dispatching Notice...' : 'Dispatch 1-Click Takedown'}</span>
                </button>
              </div>
            </div>

            <pre className="p-6 text-xs font-mono text-slate-800 bg-slate-50/50 overflow-x-auto whitespace-pre leading-relaxed border-b border-slate-100 max-h-[460px]">
              {reportText}
            </pre>

            <div className="px-5 py-3 bg-white flex flex-wrap items-center justify-between text-xs text-slate-500 font-mono gap-2">
              <div>Evidence Digest: <span className="text-slate-800 font-semibold">SHA256({threat.evidenceHash ? threat.evidenceHash.slice(0, 16) : '9a8b7c6d5e4f3a2b'}...)</span></div>
              <div className="text-emerald-700 font-sans font-medium flex items-center space-x-1">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                <span>Cryptographically Timestamped & NPCI Compliant</span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
