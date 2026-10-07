import crypto from 'crypto';
import { ThreatItem } from '../../src/types/threat';
import { db, TakedownDispatchRecord } from '../db';

export interface DispatchRequest {
  threatId: string;
  channels: ('CERT_IN' | 'NPCI_UPI' | 'REGISTRAR' | 'HOSTING_CDN')[];
  analystNotes?: string;
  urgencyLevel?: 'CRITICAL_IMMEDIATE' | 'HIGH_EXPEDITE' | 'STANDARD';
}

export interface GeneratedTakedownNotices {
  certInForm7A: string;
  npciUpiFreeze: string;
  registrarRfc2822: string;
  hostCdnAbuse: string;
  reproducibleCurl: string;
  evidencePackageDigest: string;
}

export function generateAllTakedownNotices(threat: ThreatItem): GeneratedTakedownNotices {
  const timestamp = new Date().toISOString();
  const vpas = threat.extractedUPI_VPA?.length ? threat.extractedUPI_VPA.join(', ') : 'None Detected';
  const phones = threat.extractedPhoneNumbers?.length ? threat.extractedPhoneNumbers.join(', ') : 'None Detected';
  const evidenceDigest = crypto.createHash('sha256').update(threat.domain + threat.url + timestamp).digest('hex');

  const certInForm7A = `================================================================================
INCIDENT REPORTING FORM (FORM 7A)
Indian Computer Emergency Response Team (CERT-In)
Under Section 70B of Information Technology Act, 2000 & CERT-In Cyber Security Directions
================================================================================

1. INCIDENT CLASSIFICATION:
   - Type: Payment Phishing, Fake UPI Portal & Credential Harvesting
   - Target Brand: ${threat.targetBrand}
   - Severity: ${threat.severity} (Automated Detection Confidence: ${threat.similarityScore}%)
   - Incident Tracking ID: CERTIN-${new Date().getFullYear()}-PHISH-${threat.id.toUpperCase()}

2. INFRASTRUCTURE & ATTACK VECTOR DETAILS:
   - Target URL: ${threat.url}
   - Resolved Domain: ${threat.domain}
   - Hosting IP: ${threat.ip} (${threat.country})
   - Autonomous System (ASN): ${threat.asn} - ${threat.asnName}
   - Domain Registrar: ${threat.registrar}
   - TLS Serial: ${threat.sslSerial} (Issuer: ${threat.sslIssuer})
   - Nameservers: ${threat.dnsNameservers.join(', ')}

3. FRAUDULENT PAYMENT IOCs:
   - Extracted Fake UPI VPAs: ${vpas}
   - Extracted Mule Numbers: ${phones}
   - Attributed Syndicate: ${threat.threatActorSyndicate} (${threat.campaignName})

4. DOM CREDENTIAL HARVEST & MALICE SIGNATURE:
   - Intercepts confidential 6-digit UPI PINs, Banking Passwords, and OTPs.
   - Evasion Tactics: User-Agent gating, India Geo-fencing, DevTools Traps.
   - Evidence SHA-256: ${evidenceDigest}

5. REMEDIAL ACTION REQUESTED:
   - Issue blocking order to Department of Telecommunications (DoT) under Section 69A IT Act.
   - Direct NPCI to freeze identified fraud VPAs across all UPI Switch participants.
================================================================================`;

  const npciUpiFreeze = `================================================================================
NATIONAL PAYMENTS CORPORATION OF INDIA (NPCI) — FRAUD PREVENTION NOTIFICATION
TO: NPCI UPI Risk Desk & Partner PSP Bank CSIRTs (fraud-ops@npci.org.in)
SUBJECT: [URGENT] Fraudulent UPI VPA Freezing Request — ${threat.targetBrand} Spoofing
================================================================================

Dear NPCI Risk Operations Team,

PhishNet Sentinel has detected active payment diversion and fake UPI collect lures impersonating ${threat.targetBrand}.

SUSPICIOUS VPAs / BENEFICIARY HANDLES TO FREEZE:
${threat.extractedUPI_VPA?.map(v => `  - VPA Handle: ${v} [STATUS: ACTIVE FRAUD COLLECTOR]`).join('\n') || '  - Direct Web Collect Form (Dynamic VPA routing)'}

ATTRIBUTION & TELEMETRY:
- Hosting Domain: ${threat.domain}
- Attack Mechanism: Disguised KYC verification / Cashback claim triggering UPI Collect request
- Associated Mobile Numbers: ${phones}
- Campaign: ${threat.campaignName}
- Confidence Score: ${threat.similarityScore}%

REQUESTED ACTIONS:
1. Immediate debit/credit freeze on beneficiary handles at the acquiring PSP switch.
2. Ingest associated device IMEIs & bank account roots into the NPCI Central Fraud Registry.
================================================================================`;

  const registrarRfc2822 = `From: abuse-ops@phishnet-sentinel.org
To: abuse@${threat.registrar.toLowerCase().replace(/\s+/g, '')}.com, abuse-contacts@nic.in
Subject: RFC-2822 Abuse Notification: Phishing & UPI Fraud on domain ${threat.domain}
Date: ${new Date().toUTCString()}
Message-ID: <${Date.now()}@phishnet-sentinel.org>

Dear Abuse Desk / Trust & Safety Team,

We are writing to report that the following domain registered through your services is currently hosting an active phishing operation designed to defraud Indian banking and UPI customers:

- Offending Domain: ${threat.domain}
- Full URL: ${threat.url}
- Targeted Institution: ${threat.targetBrand}
- Brand Official Domain: ${threat.genuineReferenceUrl}
- Server IP: ${threat.ip} (ASN: ${threat.asn})
- Evidence Digest: SHA-256:${evidenceDigest}

TECHNICAL EVIDENCE:
The website at this domain replicates the copyrighted branding, CSS layouts, and trademarks of ${threat.targetBrand}. It illicitly collects customer 6-digit UPI PINs and banking credentials in violation of your Acceptable Use Policy and international anti-fraud statutes.

We request the immediate suspension / DNS sinkhole of this domain.

Sincerely,
PhishNet Autonomous CSIRT Response Engine`;

  const hostCdnAbuse = `URGENT ABUSE REPORT: Host Provider ${threat.asnName} (${threat.asn})
Target IP: ${threat.ip}
Origin URL: ${threat.url}

The server at ${threat.ip} is actively hosting a malicious phishing portal impersonating ${threat.targetBrand}. The page conducts unauthorized credential harvesting and bypasses geo-filters. 

Please terminate upstream IP routing or disable this customer account immediately.
Evidence Hash: ${evidenceDigest}`;

  const reproducibleCurl = `curl -i -k -X GET "${threat.url}" \\
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" \\
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\
  -H "Accept-Language: en-IN,en-US;q=0.9,en;q=0.8,hi;q=0.7" \\
  -H "X-Forwarded-For: 49.37.12.18" \\
  --max-redirs 5`;

  return {
    certInForm7A,
    npciUpiFreeze,
    registrarRfc2822,
    hostCdnAbuse,
    reproducibleCurl,
    evidencePackageDigest: evidenceDigest
  };
}

export function dispatchTakedown(req: DispatchRequest): TakedownDispatchRecord {
  const threat = db.getThreatById(req.threatId);
  if (!threat) {
    throw new Error(`Threat with ID ${req.threatId} not found`);
  }

  const notices = generateAllTakedownNotices(threat);
  const trackingNumber = `CERTIN-${new Date().getFullYear()}-T3-${threat.id.replace('thr-', '')}`;

  const channelsList: string[] = [];
  const recipients: string[] = [];

  if (req.channels.includes('CERT_IN')) {
    channelsList.push('CERT-In Form 7A');
    recipients.push('incident@cert-in.org.in');
  }
  if (req.channels.includes('NPCI_UPI')) {
    channelsList.push('NPCI UPI Fraud Shield');
    recipients.push('fraud-ops@npci.org.in');
  }
  if (req.channels.includes('REGISTRAR')) {
    channelsList.push(`${threat.registrar} Abuse Desk`);
    recipients.push(`abuse@${threat.registrar.toLowerCase().replace(/\s+/g, '')}.com`);
  }
  if (req.channels.includes('HOSTING_CDN')) {
    channelsList.push(`${threat.asnName} Host Abuse`);
    recipients.push(`abuse@${threat.asn.toLowerCase()}.net`);
  }

  const dispatchRecord: TakedownDispatchRecord = {
    id: `disp-${Date.now().toString().slice(-4)}`,
    threatId: threat.id,
    targetDomain: threat.domain,
    targetBrand: threat.targetBrand,
    channels: channelsList,
    dispatchedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
    dispatchedBy: 'Autonomous SOC CSIRT Engine (Auto-Sign)',
    status: 'IN_PROCESS',
    trackingNumber,
    rfcNoticeExcerpt: `Takedown notice dispatched across ${channelsList.length} response channels. Evidence SHA-256: ${notices.evidencePackageDigest.substring(0, 16)}...`,
    evidenceSha256: notices.evidencePackageDigest,
    recipients
  };

  return db.recordDispatch(dispatchRecord);
}
