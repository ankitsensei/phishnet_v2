import React, { useState } from 'react';
import { FileText, Send, CheckCircle, Copy, Download } from 'lucide-react';
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
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-lg bg-[#09090b] border border-[#27272a] flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight">
            Automated Takedown Report & Evidence Package Generator
          </h2>
          <p className="text-xs text-[#a1a1aa] mt-0.5">
            Generates standardized CERT-In Form 7A, NPCI UPI Shield, and Registrar RFC-2822 abuse notices.
          </p>
        </div>

        {/* Target Selector */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-[#71717a] font-mono">Target:</span>
          <select
            value={activeThreatId}
            onChange={(e) => setActiveThreatId(e.target.value)}
            className="bg-[#121214] border border-[#27272a] text-xs rounded-md px-3 py-1.5 text-white focus:outline-none focus:border-white font-mono"
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
          { id: 'CERT_IN', label: 'CERT-In Form 7A Notice', desc: 'Government CSIRT' },
          { id: 'NPCI_UPI', label: 'NPCI UPI Fraud Desk', desc: 'VPA Freeze Directive' },
          { id: 'REGISTRAR', label: 'Registrar Abuse Desk', desc: `${threat.registrar}` },
          { id: 'HOST_CDN', label: 'Host / CDN Abuse Desk', desc: `${threat.asnName}` },
          { id: 'BANK_CSIRT', label: 'Brand Security Desk', desc: `${threat.targetBrand} CSIRT` },
        ].map((item) => (
          <button
            key={item.id}
            onClick={() => setRecipientType(item.id as any)}
            className={`flex-1 min-w-[170px] p-3 rounded-lg border text-left transition-colors ${
              recipientType === item.id
                ? 'bg-white text-black border-white'
                : 'bg-[#09090b] border-[#27272a] text-[#a1a1aa] hover:text-white hover:bg-[#121214]'
            }`}
          >
            <div className={`font-semibold text-xs ${recipientType === item.id ? 'text-black' : 'text-white'}`}>
              {item.label}
            </div>
            <div className={`text-[10px] font-mono truncate mt-0.5 ${recipientType === item.id ? 'text-[#3f3f46]' : 'text-[#71717a]'}`}>
              {item.desc}
            </div>
          </button>
        ))}
      </div>

      {/* Report Code View */}
      <div className="rounded-lg bg-[#000000] border border-[#27272a] overflow-hidden">
        <div className="px-4 py-2.5 bg-[#09090b] border-b border-[#27272a] flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-mono font-semibold text-white">
            Abuse Format: {recipientType} for {threat.domain}
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopy}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-[#121214] hover:bg-[#1f1f23] text-white border border-[#27272a] text-xs font-mono transition-colors"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-[#121214] hover:bg-[#1f1f23] text-white border border-[#27272a] text-xs font-mono transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .TXT</span>
            </button>

            <button
              onClick={handleDispatch}
              className="flex items-center space-x-1.5 px-4 py-1.5 rounded bg-white text-black hover:bg-[#e4e4e7] text-xs font-semibold shadow-sm transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{dispatched ? 'Dispatching Notice...' : 'Dispatch Automated Takedown'}</span>
            </button>
          </div>
        </div>

        <pre className="p-5 text-xs font-mono text-[#d4d4d8] bg-[#000000] overflow-x-auto whitespace-pre leading-relaxed border-b border-[#27272a] max-h-[460px]">
          {reportText}
        </pre>

        <div className="px-4 py-2.5 bg-[#09090b] flex flex-wrap items-center justify-between text-[11px] text-[#71717a] font-mono gap-2">
          <div>Integrity Digest: SHA256({threat.evidenceHash.slice(0, 16)}...)</div>
          <div className="text-white">Immutable Forensic Snapshot Timestamped</div>
        </div>
      </div>
    </div>
  );
};
