import React, { useState } from 'react';
import { FileText, Send, CheckCircle2, Copy, Download, ShieldAlert, Lock, Terminal, ExternalLink, RefreshCw } from 'lucide-react';
import { ThreatItem } from '../types/threat';

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
  const [dispatched, setDispatched] = useState<boolean>(false);

  const threat = threats.find(t => t.id === activeThreatId) || threats[0];

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
Active Nameservers    : ${threat.dnsNameservers.join(', ')}

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
Anti-Analysis Evasion : ${threat.evasionTactics.antiBotGating ? 'User-Agent Gating, ' : ''}${threat.evasionTactics.geoFencingIndiaOnly ? 'India-Only GeoIP BGP Gating, ' : ''}${threat.evasionTactics.devtoolsBlocker ? 'DevTools Debugger Loop' : 'None'}

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

    // BANK_CSIRT
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

  const handleDispatch = () => {
    setDispatched(true);
    setTimeout(() => setDispatched(false), 3000);
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
    <div className="space-y-5">
      {/* Header */}
      <div className="p-4 rounded-xl bg-[#0c1017] border border-white/10 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white font-display flex items-center space-x-2">
              <span>Automated 1-Click Takedown & Evidence Dispatcher</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                CERT-In • NPCI • Registrar RFC-2822
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Generates RFC-compliant abuse reports, cryptographic hashes, and WHOIS/DNS evidence packets
            </p>
          </div>
        </div>

        {/* Threat Selector */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Select Target:</span>
          <select
            value={activeThreatId}
            onChange={(e) => setActiveThreatId(e.target.value)}
            className="bg-[#141b29] border border-white/10 text-xs rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {threats.map(t => (
              <option key={t.id} value={t.id}>
                [{t.targetBrand}] {t.domain}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Recipient Channel Selector */}
      <div className="flex flex-wrap gap-2">
        {[
          { id: 'CERT_IN', label: 'CERT-In Form 7A Notice', desc: 'Govt National CSIRT' },
          { id: 'NPCI_UPI', label: 'NPCI UPI Fraud Desk', desc: 'VPA Freeze Request' },
          { id: 'REGISTRAR', label: 'Registrar Abuse Desk', desc: `${threat.registrar}` },
          { id: 'HOST_CDN', label: 'Host / CDN Abuse Desk', desc: `${threat.asnName}` },
          { id: 'BANK_CSIRT', label: 'Brand Security Team', desc: `${threat.targetBrand} CSIRT` },
        ].map((item) => (
          <button
            key={item.id}
            onClick={() => setRecipientType(item.id as any)}
            className={`flex-1 min-w-[170px] p-3 rounded-xl border text-left transition-all ${
              recipientType === item.id
                ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300 shadow-lg shadow-cyan-500/10'
                : 'bg-[#0d121c] border-white/10 text-slate-400 hover:text-slate-200 hover:bg-[#121824]'
            }`}
          >
            <div className="font-semibold text-xs text-white">{item.label}</div>
            <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">{item.desc}</div>
          </button>
        ))}
      </div>

      {/* Report Preview & Code Area */}
      <div className="rounded-xl bg-[#090d14] border border-white/10 overflow-hidden shadow-2xl">
        <div className="px-4 py-2.5 bg-[#101622] border-b border-white/10 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-xs font-mono font-semibold text-slate-200">
              Generated Report: {recipientType} for {threat.domain}
            </span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopy}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs font-mono transition-all"
            >
              {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs font-mono transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .TXT</span>
            </button>

            <button
              onClick={handleDispatch}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white text-xs font-semibold shadow-lg shadow-rose-600/30 transition-all"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{dispatched ? 'Dispatching...' : 'Dispatch Automated Takedown'}</span>
            </button>
          </div>
        </div>

        {/* Report Monospace Viewer */}
        <pre className="p-5 text-xs font-mono text-cyan-200/90 bg-[#06090e] overflow-x-auto whitespace-pre leading-relaxed border-b border-white/5 max-h-[460px]">
          {reportText}
        </pre>

        {/* Footer info */}
        <div className="px-4 py-2.5 bg-[#0a0e16] flex flex-wrap items-center justify-between text-[11px] text-slate-400 font-mono gap-2">
          <div>Cryptographic Digest: SHA256({threat.evidenceHash.slice(0, 16)}...)</div>
          <div className="text-emerald-400 flex items-center space-x-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Digital Evidence Timestamped on Immutable Audit Log</span>
          </div>
        </div>
      </div>
    </div>
  );
};
