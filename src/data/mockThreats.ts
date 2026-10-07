import { ThreatItem, CampaignCluster, GraphNode, GraphLink, ModelMetrics, CTLogEntry, TargetBrand } from '../types/threat';


export const INITIAL_CAMPAIGNS: CampaignCluster[] = [
  {
    id: 'camp-yono-01',
    name: 'Op YONO-Shield Harvester',
    syndicate: 'ShadowVPA Syndicate (Jamtara-NCR Cell)',
    riskScore: 98,
    threatLevel: 'CRITICAL',
    firstSeen: '2026-09-18 04:12:00',
    lastSeen: '2026-10-07 14:20:11',
    activeNodesCount: 24,
    domainsCount: 14,
    ipsCount: 4,
    vpasCount: 6,
    targetedBrands: ['SBI YONO', 'PhonePe'],
    financialLossEstimateINR: '₹4.28 Crore',
    takedownSuccessRate: 88,
    status: 'ACTIVE'
  },
  {
    id: 'camp-paytm-refund',
    name: 'Paytm Instant Cashback Ring',
    syndicate: 'GoldenQR Cyber Group',
    riskScore: 94,
    threatLevel: 'CRITICAL',
    firstSeen: '2026-09-24 11:30:00',
    lastSeen: '2026-10-07 13:45:22',
    activeNodesCount: 18,
    domainsCount: 9,
    ipsCount: 3,
    vpasCount: 5,
    targetedBrands: ['Paytm', 'Google Pay'],
    financialLossEstimateINR: '₹1.85 Crore',
    takedownSuccessRate: 92,
    status: 'ACTIVE'
  },
  {
    id: 'camp-hdfc-kyc',
    name: 'HDFC NetBanking Credential Grabber',
    syndicate: 'MuleMatrix Network',
    riskScore: 89,
    threatLevel: 'HIGH',
    firstSeen: '2026-10-01 08:15:00',
    lastSeen: '2026-10-07 12:10:04',
    activeNodesCount: 12,
    domainsCount: 7,
    ipsCount: 2,
    vpasCount: 3,
    targetedBrands: ['HDFC Bank'],
    financialLossEstimateINR: '₹95 Lakh',
    takedownSuccessRate: 75,
    status: 'ACTIVE'
  },
  {
    id: 'camp-bhim-apk',
    name: 'BHIM-Shield Dropper Trojan (APK)',
    syndicate: 'AndroidStealer-IN',
    riskScore: 96,
    threatLevel: 'CRITICAL',
    firstSeen: '2026-09-28 14:00:00',
    lastSeen: '2026-10-07 14:15:30',
    activeNodesCount: 15,
    domainsCount: 6,
    ipsCount: 4,
    vpasCount: 4,
    targetedBrands: ['BHIM UPI', 'ICICI iMobile'],
    financialLossEstimateINR: '₹2.10 Crore',
    takedownSuccessRate: 64,
    status: 'ACTIVE'
  }
];

export const INITIAL_THREATS: ThreatItem[] = [
  {
    id: 'thr-8901',
    url: 'https://sbi-yono-pan-kyc-update.live/verify-account.php',
    domain: 'sbi-yono-pan-kyc-update.live',
    targetBrand: 'SBI YONO',
    threatType: 'FAKE_UPI_PORTAL',
    discoverySource: 'CT_LOGS',
    discoveryTimestamp: '2026-10-07 14:18:24',
    severity: 'CRITICAL',
    status: 'CONFIRMED_PHISH',
    similarityScore: 98.4,
    pHashDistance: 3,
    structuralSSIM: 0.962,
    domEditDistance: 0.04,
    logoConfidence: 99.1,
    ip: '185.220.101.44',
    asn: 'AS44050',
    asnName: 'Petersburg Offshore Networks Corp',
    country: 'Seychelles (Hosted: RU)',
    countryCode: 'SC',
    registrar: 'NameSilo, LLC',
    sslIssuer: "Let's Encrypt Authority E6",
    sslSerial: '04a29ef1b32948c201',
    dnsNameservers: ['ns1.bulletproof-dns.top', 'ns2.bulletproof-dns.top'],
    extractedUPI_VPA: ['sbikyc.refund99@paytm', 'instantverif.sbi@ybl', 'mule.sharma90@icici'],
    extractedPhoneNumbers: ['+91 98765 43210', '+91 88221 09483'],
    extractedBankAccounts: ['SBI A/C: 30492819201 (IFSC: SBIN0001824)'],
    qrCodePayload: 'upi://pay?pa=sbikyc.refund99@paytm&pn=SBI_KYC_VERIFICATION&am=1.00&cu=INR&tn=KYC_Activation_Refund',
    campaignId: 'camp-yono-01',
    campaignName: 'Op YONO-Shield Harvester',
    threatActorSyndicate: 'ShadowVPA Syndicate (Jamtara-NCR Cell)',
    evasionTactics: {
      antiBotGating: true,
      canvasFingerprinting: true,
      geoFencingIndiaOnly: true,
      userAgentFiltering: true,
      devtoolsBlocker: true,
      dynamicDomRedirection: true,
      fakeSslBadge: true
    },
    screenshotUrl: '/assets/evidence/sbi_clone.webp',
    genuineReferenceUrl: 'https://www.onlinesbi.sbi',
    evidenceHash: 'a8b792e3d90f41c3098fbe8402a7b6291a8e94e207b99c1583d47012efc4d98a',
    timeline: [
      { time: '14:18:24', event: 'CT Log Stream emitted cert for domain sbi-yono-pan-kyc-update.live', actor: 'CertStream Crawler' },
      { time: '14:18:27', event: 'Headless Browser extracted DOM and rendered viewport screenshot', actor: 'Visual Engine' },
      { time: '14:18:29', event: 'pHash computed: 3 dist from SBI YONO canonical (SSIM: 0.962). Evasion detected.', actor: 'AI Similarity Engine' },
      { time: '14:18:31', event: 'Extracted UPI Collect VPA sbikyc.refund99@paytm and mapped to ShadowVPA Campaign', actor: 'Graph Correlator' },
      { time: '14:19:00', event: 'Status escalated to CONFIRMED_PHISH. Auto takedown packet prepared.', actor: 'Analyst System' }
    ]
  },
  {
    id: 'thr-8902',
    url: 'https://phonepe-rewards-claim-5000.top/scratch-card.html',
    domain: 'phonepe-rewards-claim-5000.top',
    targetBrand: 'PhonePe',
    threatType: 'FAKE_UPI_PORTAL',
    discoverySource: 'SMS_STREAM',
    discoveryTimestamp: '2026-10-07 14:05:12',
    severity: 'CRITICAL',
    status: 'TAKEDOWN_DISPATCHED',
    similarityScore: 96.8,
    pHashDistance: 4,
    structuralSSIM: 0.945,
    domEditDistance: 0.08,
    logoConfidence: 98.4,
    ip: '104.21.49.182',
    asn: 'AS13335',
    asnName: 'Cloudflare, Inc.',
    country: 'United States',
    countryCode: 'US',
    registrar: 'Hostinger Operations, UAB',
    sslIssuer: 'Cloudflare Inc ECC CA-3',
    sslSerial: '039b81f9a2e8820c77',
    dnsNameservers: ['dora.ns.cloudflare.com', 'walt.ns.cloudflare.com'],
    extractedUPI_VPA: ['phonepe.reward.claim@axl', 'cashback.desk77@ibl'],
    extractedPhoneNumbers: ['+91 70041 29841'],
    qrCodePayload: 'upi://pay?pa=phonepe.reward.claim@axl&pn=PhonePe_Reward_Disbursement&am=4999.00&cu=INR&tn=Cashback_PIN_Confirm',
    campaignId: 'camp-yono-01',
    campaignName: 'Op YONO-Shield Harvester',
    threatActorSyndicate: 'ShadowVPA Syndicate (Jamtara-NCR Cell)',
    evasionTactics: {
      antiBotGating: true,
      canvasFingerprinting: false,
      geoFencingIndiaOnly: true,
      userAgentFiltering: true,
      devtoolsBlocker: true,
      dynamicDomRedirection: false,
      fakeSslBadge: true
    },
    screenshotUrl: '/assets/evidence/phonepe_clone.webp',
    genuineReferenceUrl: 'https://www.phonepe.com',
    evidenceHash: 'c7d2194b8e010a34589dff52981ac288b50e4177d2948bf8238120bba5e917d0',
    timeline: [
      { time: '14:05:12', event: 'Lure SMS received: "Congrats! ₹4,999 cashback credited in PhonePe. Claim now..."', actor: 'SMS Stream Parser' },
      { time: '14:05:18', event: 'Simulated UPI Scratch card layout analyzed; fake PIN-harvesting modal found', actor: 'Behavioural Engine' },
      { time: '14:06:00', event: 'Automated CERT-In & Cloudflare Abuse takedown notices dispatched', actor: 'Auto Takedown Robot' }
    ]
  },
  {
    id: 'thr-8903',
    url: 'https://paytm-kyc-unblock-portal.in/login',
    domain: 'paytm-kyc-unblock-portal.in',
    targetBrand: 'Paytm',
    threatType: 'FAKE_PAYMENT_GATEWAY',
    discoverySource: 'USER_REPORT',
    discoveryTimestamp: '2026-10-07 13:42:10',
    severity: 'HIGH',
    status: 'CONFIRMED_PHISH',
    similarityScore: 94.2,
    pHashDistance: 6,
    structuralSSIM: 0.918,
    domEditDistance: 0.11,
    logoConfidence: 96.7,
    ip: '194.38.20.71',
    asn: 'AS49870',
    asnName: 'Alavisa Host BG',
    country: 'Bulgaria',
    countryCode: 'BG',
    registrar: 'PublicDomainRegistry',
    sslIssuer: 'ZeroSSL RSA Domain Secure',
    sslSerial: '08129fa901248ccb',
    dnsNameservers: ['dns1.paytm-fastdns.org', 'dns2.paytm-fastdns.org'],
    extractedUPI_VPA: ['paytmkyc.desk@paytm', 'refundmerch.hub@ybl'],
    extractedPhoneNumbers: ['+91 91234 56789'],
    extractedBankAccounts: ['Paytm Payments Bank: 919876543210'],
    campaignId: 'camp-paytm-refund',
    campaignName: 'Paytm Instant Cashback Ring',
    threatActorSyndicate: 'GoldenQR Cyber Group',
    evasionTactics: {
      antiBotGating: true,
      canvasFingerprinting: true,
      geoFencingIndiaOnly: true,
      userAgentFiltering: true,
      devtoolsBlocker: false,
      dynamicDomRedirection: true,
      fakeSslBadge: true
    },
    screenshotUrl: '/assets/evidence/paytm_clone.webp',
    genuineReferenceUrl: 'https://paytm.com',
    evidenceHash: 'b45f91e847c20a1128394857d938210495867182903847561928374650192837',
    timeline: [
      { time: '13:42:10', event: 'Bank Security Desk relayed suspicious domain flagged by victim', actor: 'Bank CSIRT' },
      { time: '13:42:25', event: 'Visual fingerprinting matched Paytm merchant portal 94.2%', actor: 'Visual Engine' },
      { time: '13:43:00', event: 'Linked to GoldenQR Campaign IP 194.38.20.71', actor: 'Campaign Graph' }
    ]
  },
  {
    id: 'thr-8904',
    url: 'https://download-yono-sbi-v4.apk.store/files/SBI_Yono_Update.apk',
    domain: 'download-yono-sbi-v4.apk.store',
    targetBrand: 'SBI YONO',
    threatType: 'MALICIOUS_APK',
    discoverySource: 'BANK_CSIRT_INTEL',
    discoveryTimestamp: '2026-10-07 13:10:00',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    similarityScore: 99.2,
    pHashDistance: 2,
    structuralSSIM: 0.985,
    domEditDistance: 0.02,
    logoConfidence: 99.5,
    ip: '45.142.214.99',
    asn: 'AS200000',
    asnName: 'CyberShield Bulletproof NV',
    country: 'Panama',
    countryCode: 'PA',
    registrar: 'Tucows Domains Inc.',
    sslIssuer: "Let's Encrypt Authority E6",
    sslSerial: '0198273645bbfa90',
    dnsNameservers: ['ns1.panama-secure.is', 'ns2.panama-secure.is'],
    apkPackageName: 'com.sbi.lotusapply.banking',
    apkSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    extractedUPI_VPA: ['sbiapp.mule01@axl'],
    extractedPhoneNumbers: ['+91 80112 34567'],
    campaignId: 'camp-yono-01',
    campaignName: 'Op YONO-Shield Harvester',
    threatActorSyndicate: 'ShadowVPA Syndicate (Jamtara-NCR Cell)',
    evasionTactics: {
      antiBotGating: true,
      canvasFingerprinting: true,
      geoFencingIndiaOnly: false,
      userAgentFiltering: true,
      devtoolsBlocker: true,
      dynamicDomRedirection: true,
      fakeSslBadge: false
    },
    screenshotUrl: '/assets/evidence/apk_clone.webp',
    genuineReferenceUrl: 'https://play.google.com/store/apps/details?id=com.sbi.lotusapply',
    evidenceHash: '739281a9bc382740918237465928374659283746592837465928374659283746',
    timeline: [
      { time: '13:10:00', event: 'Malware dropper APK discovered hosted on off-shore domain', actor: 'APK Scanner' },
      { time: '13:10:15', event: 'Static Analysis: Found RECEIVE_SMS, READ_PHONE_STATE, BIND_ACCESSIBILITY_SERVICE', actor: 'Sandbox Pipeline' },
      { time: '13:10:30', event: 'Detected UPI Intent hijacker hook for upi://pay and C2 endpoint', actor: 'Static Analyzer' }
    ]
  },
  {
    id: 'thr-8905',
    url: 'https://gpay-scratch-voucher-999.in/redeem',
    domain: 'gpay-scratch-voucher-999.in',
    targetBrand: 'Google Pay',
    threatType: 'QR_PHISHING',
    discoverySource: 'SMS_STREAM',
    discoveryTimestamp: '2026-10-07 12:45:00',
    severity: 'HIGH',
    status: 'CONFIRMED_PHISH',
    similarityScore: 92.5,
    pHashDistance: 7,
    structuralSSIM: 0.901,
    domEditDistance: 0.12,
    logoConfidence: 95.2,
    ip: '104.21.49.182',
    asn: 'AS13335',
    asnName: 'Cloudflare, Inc.',
    country: 'United States',
    countryCode: 'US',
    registrar: 'BigRock Solutions Ltd',
    sslIssuer: 'Cloudflare Inc ECC CA-3',
    sslSerial: '059a8820c81249b',
    dnsNameservers: ['curt.ns.cloudflare.com', 'lola.ns.cloudflare.com'],
    extractedUPI_VPA: ['gpayvoucher.win@okaxis', 'claim.gpayreward@oksbi'],
    qrCodePayload: 'upi://pay?pa=gpayvoucher.win@okaxis&pn=GPay_Cashback_Reward&am=2499.00&cu=INR&tn=Reward_Claim_Verification',
    campaignId: 'camp-paytm-refund',
    campaignName: 'Paytm Instant Cashback Ring',
    threatActorSyndicate: 'GoldenQR Cyber Group',
    evasionTactics: {
      antiBotGating: true,
      canvasFingerprinting: false,
      geoFencingIndiaOnly: true,
      userAgentFiltering: true,
      devtoolsBlocker: false,
      dynamicDomRedirection: false,
      fakeSslBadge: true
    },
    screenshotUrl: '/assets/evidence/gpay_clone.webp',
    genuineReferenceUrl: 'https://pay.google.com/intl/en_in/about/',
    evidenceHash: '5928374610293847561029384756102938475610293847561029384756102938',
    timeline: [
      { time: '12:45:00', event: 'Smishing SMS alert decoded containing QR voucher redirect', actor: 'SMS Parser' },
      { time: '12:45:10', event: 'QR code payload contains malicious merchant debit VPA', actor: 'QR Analyzer' }
    ]
  },
  {
    id: 'thr-8906',
    url: 'https://hdfc-netbanking-session-restore.info/ebank/login',
    domain: 'hdfc-netbanking-session-restore.info',
    targetBrand: 'HDFC Bank',
    threatType: 'FAKE_PAYMENT_GATEWAY',
    discoverySource: 'CT_LOGS',
    discoveryTimestamp: '2026-10-07 12:15:20',
    severity: 'HIGH',
    status: 'TAKEN_DOWN',
    similarityScore: 97.1,
    pHashDistance: 4,
    structuralSSIM: 0.954,
    domEditDistance: 0.05,
    logoConfidence: 98.9,
    ip: '185.196.8.12',
    asn: 'AS57523',
    asnName: 'Chang Way Technologies Co.',
    country: 'Hong Kong',
    countryCode: 'HK',
    registrar: 'Dynadot Inc',
    sslIssuer: "Let's Encrypt Authority E6",
    sslSerial: '0281749102848102',
    dnsNameservers: ['ns1.dynadot.com', 'ns2.dynadot.com'],
    extractedUPI_VPA: ['hdfcsecure.auth@ybl'],
    extractedPhoneNumbers: ['+91 99887 76655'],
    campaignId: 'camp-hdfc-kyc',
    campaignName: 'HDFC NetBanking Credential Grabber',
    threatActorSyndicate: 'MuleMatrix Network',
    evasionTactics: {
      antiBotGating: true,
      canvasFingerprinting: true,
      geoFencingIndiaOnly: true,
      userAgentFiltering: true,
      devtoolsBlocker: true,
      dynamicDomRedirection: true,
      fakeSslBadge: true
    },
    screenshotUrl: '/assets/evidence/hdfc_clone.webp',
    genuineReferenceUrl: 'https://netbanking.hdfcbank.com',
    evidenceHash: '8472910485720193847501928374650192837465019283746501928374650192',
    timeline: [
      { time: '12:15:20', event: 'CT Log emitted domain registration', actor: 'CT Stream' },
      { time: '12:17:00', event: 'Takedown notice received by Dynadot Abuse & DNS suspended', actor: 'Registrar API' },
      { time: '12:20:00', event: 'Domain confirmed offline (NXDOMAIN). Marked as TAKEN_DOWN.', actor: 'Health Checker' }
    ]
  }
];

export const MOCK_GRAPH_DATA: { nodes: GraphNode[]; links: GraphLink[] } = {
  nodes: [
    // Campaigns
    { id: 'camp-yono-01', label: 'Op YONO-Shield Harvester', type: 'CAMPAIGN', severity: 'CRITICAL', details: { syndicate: 'ShadowVPA Syndicate', loss: '₹4.28 Cr' } },
    { id: 'camp-paytm-refund', label: 'Paytm Instant Cashback Ring', type: 'CAMPAIGN', severity: 'CRITICAL', details: { syndicate: 'GoldenQR Cyber Group', loss: '₹1.85 Cr' } },
    { id: 'camp-hdfc-kyc', label: 'HDFC NetBanking Grabber', type: 'CAMPAIGN', severity: 'HIGH', details: { syndicate: 'MuleMatrix Network', loss: '₹95 Lakh' } },

    // Domains
    { id: 'sbi-yono-pan-kyc-update.live', label: 'sbi-yono-pan-kyc-update.live', type: 'DOMAIN', severity: 'CRITICAL', campaignId: 'camp-yono-01' },
    { id: 'phonepe-rewards-claim-5000.top', label: 'phonepe-rewards-claim-5000.top', type: 'DOMAIN', severity: 'CRITICAL', campaignId: 'camp-yono-01' },
    { id: 'download-yono-sbi-v4.apk.store', label: 'download-yono-sbi-v4.apk.store', type: 'DOMAIN', severity: 'CRITICAL', campaignId: 'camp-yono-01' },
    { id: 'sbi-reward-points-redeem.xyz', label: 'sbi-reward-points-redeem.xyz', type: 'DOMAIN', severity: 'HIGH', campaignId: 'camp-yono-01' },
    { id: 'paytm-kyc-unblock-portal.in', label: 'paytm-kyc-unblock-portal.in', type: 'DOMAIN', severity: 'HIGH', campaignId: 'camp-paytm-refund' },
    { id: 'gpay-scratch-voucher-999.in', label: 'gpay-scratch-voucher-999.in', type: 'DOMAIN', severity: 'HIGH', campaignId: 'camp-paytm-refund' },
    { id: 'paytm-cashback-instant500.top', label: 'paytm-cashback-instant500.top', type: 'DOMAIN', severity: 'HIGH', campaignId: 'camp-paytm-refund' },
    { id: 'hdfc-netbanking-session-restore.info', label: 'hdfc-netbanking-session-restore.info', type: 'DOMAIN', severity: 'HIGH', campaignId: 'camp-hdfc-kyc' },
    { id: 'hdfc-pan-update-alert.online', label: 'hdfc-pan-update-alert.online', type: 'DOMAIN', severity: 'HIGH', campaignId: 'camp-hdfc-kyc' },

    // IPs & ASNs
    { id: 'ip-185.220.101.44', label: '185.220.101.44 (RU Bulletproof)', type: 'IP', severity: 'CRITICAL' },
    { id: 'ip-104.21.49.182', label: '104.21.49.182 (Cloudflare CDN)', type: 'IP', severity: 'MEDIUM' },
    { id: 'ip-194.38.20.71', label: '194.38.20.71 (Alavisa BG)', type: 'IP', severity: 'HIGH' },
    { id: 'ip-45.142.214.99', label: '45.142.214.99 (Panama C2)', type: 'IP', severity: 'CRITICAL' },
    { id: 'asn-44050', label: 'AS44050 Petersburg Offshore', type: 'ASN', severity: 'CRITICAL' },
    { id: 'asn-13335', label: 'AS13335 Cloudflare Proxy', type: 'ASN', severity: 'LOW' },

    // Malicious UPI VPAs
    { id: 'vpa-sbikyc.refund99@paytm', label: 'sbikyc.refund99@paytm', type: 'UPI_VPA', severity: 'CRITICAL', details: { bank: 'Paytm Payments Bank', volume: '₹62L' } },
    { id: 'vpa-instantverif.sbi@ybl', label: 'instantverif.sbi@ybl', type: 'UPI_VPA', severity: 'CRITICAL', details: { bank: 'Yes Bank', volume: '₹48L' } },
    { id: 'vpa-phonepe.reward.claim@axl', label: 'phonepe.reward.claim@axl', type: 'UPI_VPA', severity: 'CRITICAL', details: { bank: 'Axis Bank', volume: '₹91L' } },
    { id: 'vpa-paytmkyc.desk@paytm', label: 'paytmkyc.desk@paytm', type: 'UPI_VPA', severity: 'HIGH', details: { bank: 'Paytm Payments Bank', volume: '₹34L' } },
    { id: 'vpa-gpayvoucher.win@okaxis', label: 'gpayvoucher.win@okaxis', type: 'UPI_VPA', severity: 'HIGH', details: { bank: 'Axis Bank', volume: '₹29L' } },
    { id: 'vpa-hdfcsecure.auth@ybl', label: 'hdfcsecure.auth@ybl', type: 'UPI_VPA', severity: 'HIGH', details: { bank: 'Yes Bank', volume: '₹19L' } },

    // Mule Phone Numbers
    { id: 'phone-9876543210', label: '+91 98765 43210 (Jamtara Node)', type: 'PHONE', severity: 'HIGH' },
    { id: 'phone-7004129841', label: '+91 70041 29841 (SMS Botnet)', type: 'PHONE', severity: 'HIGH' },
    { id: 'phone-9123456789', label: '+91 91234 56789 (WhatsApp Lure)', type: 'PHONE', severity: 'MEDIUM' },

    // Malware APKs
    { id: 'apk-sbi-lotus', label: 'SBI_Yono_Update.apk (SHA: e3b0c...)', type: 'APK', severity: 'CRITICAL', details: { package: 'com.sbi.lotusapply.banking', permissions: 14 } }
  ],
  links: [
    // Campaign Associations
    { source: 'sbi-yono-pan-kyc-update.live', target: 'camp-yono-01', relationship: 'MEMBER_OF', confidence: 0.99 },
    { source: 'phonepe-rewards-claim-5000.top', target: 'camp-yono-01', relationship: 'MEMBER_OF', confidence: 0.98 },
    { source: 'download-yono-sbi-v4.apk.store', target: 'camp-yono-01', relationship: 'MEMBER_OF', confidence: 0.99 },
    { source: 'sbi-reward-points-redeem.xyz', target: 'camp-yono-01', relationship: 'MEMBER_OF', confidence: 0.95 },
    { source: 'paytm-kyc-unblock-portal.in', target: 'camp-paytm-refund', relationship: 'MEMBER_OF', confidence: 0.97 },
    { source: 'gpay-scratch-voucher-999.in', target: 'camp-paytm-refund', relationship: 'MEMBER_OF', confidence: 0.94 },
    { source: 'paytm-cashback-instant500.top', target: 'camp-paytm-refund', relationship: 'MEMBER_OF', confidence: 0.96 },
    { source: 'hdfc-netbanking-session-restore.info', target: 'camp-hdfc-kyc', relationship: 'MEMBER_OF', confidence: 0.98 },
    { source: 'hdfc-pan-update-alert.online', target: 'camp-hdfc-kyc', relationship: 'MEMBER_OF', confidence: 0.95 },

    // Hosting Infrastructure
    { source: 'sbi-yono-pan-kyc-update.live', target: 'ip-185.220.101.44', relationship: 'HOSTED_ON', confidence: 1.0 },
    { source: 'sbi-reward-points-redeem.xyz', target: 'ip-185.220.101.44', relationship: 'HOSTED_ON', confidence: 1.0 },
    { source: 'ip-185.220.101.44', target: 'asn-44050', relationship: 'ROUTES_THROUGH', confidence: 1.0 },

    { source: 'phonepe-rewards-claim-5000.top', target: 'ip-104.21.49.182', relationship: 'HOSTED_ON', confidence: 1.0 },
    { source: 'gpay-scratch-voucher-999.in', target: 'ip-104.21.49.182', relationship: 'HOSTED_ON', confidence: 1.0 },
    { source: 'ip-104.21.49.182', target: 'asn-13335', relationship: 'ROUTES_THROUGH', confidence: 1.0 },

    { source: 'paytm-kyc-unblock-portal.in', target: 'ip-194.38.20.71', relationship: 'HOSTED_ON', confidence: 1.0 },
    { source: 'paytm-cashback-instant500.top', target: 'ip-194.38.20.71', relationship: 'HOSTED_ON', confidence: 1.0 },

    { source: 'download-yono-sbi-v4.apk.store', target: 'ip-45.142.214.99', relationship: 'HOSTED_ON', confidence: 1.0 },
    { source: 'download-yono-sbi-v4.apk.store', target: 'apk-sbi-lotus', relationship: 'DISTRIBUTES_APK', confidence: 1.0 },

    // UPI Payment VPAs
    { source: 'sbi-yono-pan-kyc-update.live', target: 'vpa-sbikyc.refund99@paytm', relationship: 'COLLECTS_VIA', confidence: 0.99 },
    { source: 'sbi-yono-pan-kyc-update.live', target: 'vpa-instantverif.sbi@ybl', relationship: 'COLLECTS_VIA', confidence: 0.98 },
    { source: 'phonepe-rewards-claim-5000.top', target: 'vpa-phonepe.reward.claim@axl', relationship: 'COLLECTS_VIA', confidence: 0.99 },
    { source: 'paytm-kyc-unblock-portal.in', target: 'vpa-paytmkyc.desk@paytm', relationship: 'COLLECTS_VIA', confidence: 0.99 },
    { source: 'gpay-scratch-voucher-999.in', target: 'vpa-gpayvoucher.win@okaxis', relationship: 'COLLECTS_VIA', confidence: 0.97 },
    { source: 'hdfc-netbanking-session-restore.info', target: 'vpa-hdfcsecure.auth@ybl', relationship: 'COLLECTS_VIA', confidence: 0.98 },

    // Mule Phones & Shared Infrastructure
    { source: 'sbi-yono-pan-kyc-update.live', target: 'phone-9876543210', relationship: 'ASSOCIATED_PHONE', confidence: 0.92 },
    { source: 'phonepe-rewards-claim-5000.top', target: 'phone-7004129841', relationship: 'ASSOCIATED_PHONE', confidence: 0.95 },
    { source: 'paytm-kyc-unblock-portal.in', target: 'phone-9123456789', relationship: 'ASSOCIATED_PHONE', confidence: 0.90 },
    { source: 'vpa-sbikyc.refund99@paytm', target: 'phone-9876543210', relationship: 'ASSOCIATED_PHONE', confidence: 0.96 }
  ]
};

export const MOCK_MODEL_METRICS: ModelMetrics = {
  precision: 99.42,
  recall: 98.71,
  f1Score: 99.06,
  accuracy: 99.18,
  falsePositiveRate: 0.12,
  aucRoc: 0.9984,
  averageLatencyMs: 44.6,
  totalTestedSamples: 10450,
  truePositives: 5132,
  falsePositives: 6,
  trueNegatives: 5244,
  falseNegatives: 68
};

export const SAMPLE_CT_LOG_STREAM: CTLogEntry[] = [
  { id: 'ct-101', domain: 'sbi-yono-pan-kyc-update.live', issuer: "Let's Encrypt E6", timestamp: '14:28:20', matchedBrand: 'SBI YONO', riskScore: 98, isFlagged: true, fingerprint: 'SHA256:4a81..c290' },
  { id: 'ct-102', domain: 'api-checkout.shopify.com', issuer: 'DigiCert Global Root G2', timestamp: '14:28:18', riskScore: 2, isFlagged: false, fingerprint: 'SHA256:88fb..0112' },
  { id: 'ct-103', domain: 'phonepe-cashback-instant-in.top', issuer: 'Cloudflare Inc ECC CA-3', timestamp: '14:28:15', matchedBrand: 'PhonePe', riskScore: 95, isFlagged: true, fingerprint: 'SHA256:109a..33bf' },
  { id: 'ct-104', domain: 'analytics.google.com', issuer: 'GTS CA 1C3', timestamp: '14:28:12', riskScore: 1, isFlagged: false, fingerprint: 'SHA256:ef29..00ab' },
  { id: 'ct-105', domain: 'hdfc-netbanking-otp-verify.xyz', issuer: 'ZeroSSL RSA CA', timestamp: '14:28:09', matchedBrand: 'HDFC Bank', riskScore: 94, isFlagged: true, fingerprint: 'SHA256:cc91..fa20' },
  { id: 'ct-106', domain: 'cloud.microsoft.com', issuer: 'Microsoft Azure TLS CA', timestamp: '14:28:05', riskScore: 1, isFlagged: false, fingerprint: 'SHA256:77bc..9912' },
  { id: 'ct-107', domain: 'paytm-merchant-refund-999.in', issuer: "Let's Encrypt E5", timestamp: '14:28:01', matchedBrand: 'Paytm', riskScore: 96, isFlagged: true, fingerprint: 'SHA256:a24e..1198' },
  { id: 'ct-108', domain: 'bhim-upi-reward-instant.link', issuer: 'Sectigo RSA Domain Validation', timestamp: '14:27:55', matchedBrand: 'BHIM UPI', riskScore: 91, isFlagged: true, fingerprint: 'SHA256:dd04..88ae' }
];

export const GENUINE_BRAND_TEMPLATES: Record<TargetBrand, {
  name: string;
  officialDomain: string;
  officialVpaHandleSuffixes: string[];
  canonicalLogoUrl: string;
  colorTheme: string;
  securityNotice: string;
  commonLureVectors: string[];
}> = {
  'PhonePe': {
    name: 'PhonePe Private Limited',
    officialDomain: 'phonepe.com',
    officialVpaHandleSuffixes: ['@ybl', '@ibl', '@axl'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1622979135225-d2ba269bc1df?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#5f259f',
    securityNotice: 'PhonePe never asks for UPI PIN to receive money or cashback.',
    commonLureVectors: ['Cashback Scratch Card', 'Merchant Refund', 'Lottery Prize']
  },
  'Paytm': {
    name: 'One97 Communications (Paytm)',
    officialDomain: 'paytm.com',
    officialVpaHandleSuffixes: ['@paytm', '@ptyes', '@pthdfc', '@ptaxis'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1559526324-4b87b5e36e44?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#00b9f1',
    securityNotice: 'Paytm never requires KYC via any third-party app or APK download.',
    commonLureVectors: ['Wallet KYC Expiry', 'Fastag Recharge Failure', 'Postpaid Bill Refund']
  },
  'Google Pay': {
    name: 'Google India Digital Services',
    officialDomain: 'pay.google.com',
    officialVpaHandleSuffixes: ['@oksbi', '@okhdfcbank', '@okaxis', '@okicici'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1614680376593-902f749f7ffc?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#4285f4',
    securityNotice: 'Google Pay rewards are credited directly without scanning any external QR code.',
    commonLureVectors: ['Voucher QR Code', 'GPay Scratch Card', 'Google Tez Diwali Bonus']
  },
  'SBI YONO': {
    name: 'State Bank of India',
    officialDomain: 'onlinesbi.sbi / sbiyono.sbi',
    officialVpaHandleSuffixes: ['@sbi', '@sbin'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1541872703-74c5e44368f9?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#22409a',
    securityNotice: 'SBI never sends SMS links to unblock YONO accounts or update PAN details.',
    commonLureVectors: ['YONO Account Blocked', 'PAN / Aadhaar Linking Deadline', 'Reward Points Expiry']
  },
  'HDFC Bank': {
    name: 'HDFC Bank Limited',
    officialDomain: 'hdfcbank.com',
    officialVpaHandleSuffixes: ['@hdfcbank'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#004c8f',
    securityNotice: 'HDFC Bank will never ask for NetBanking password, IPIN, or OTP via SMS links.',
    commonLureVectors: ['NetBanking Session Expired', 'Credit Card Reward Conversion', 'Electricity Bill Debit']
  },
  'ICICI iMobile': {
    name: 'ICICI Bank Limited',
    officialDomain: 'icicibank.com',
    officialVpaHandleSuffixes: ['@icici'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1607604276583-eef5d076aa5f?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#ae282e',
    securityNotice: 'iMobile Pay activation requires only official Play Store app.',
    commonLureVectors: ['iMobile Deactivation Alert', 'Fixed Deposit Bonus', 'Cheque Clearance Pending']
  },
  'BHIM UPI': {
    name: 'National Payments Corporation of India (NPCI)',
    officialDomain: 'bhimupi.org.in',
    officialVpaHandleSuffixes: ['@upi'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1622979135225-d2ba269bc1df?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#009746',
    securityNotice: 'Entering your UPI PIN always DEBITS money from your account, never credits it.',
    commonLureVectors: ['PM Scheme Subsidy', 'Govt Grant Claim', 'Direct Benefit Transfer']
  },
  'Axis Bank': {
    name: 'Axis Bank Limited',
    officialDomain: 'axisbank.com',
    officialVpaHandleSuffixes: ['@axisbank'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1541872703-74c5e44368f9?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#97144d',
    securityNotice: 'Axis Bank alerts will never request PIN or debit card CVV.',
    commonLureVectors: ['EDGE Rewards Expiry', 'Credit Limit Enhancement']
  },
  'Cred': {
    name: 'Dreamplug Technologies (CRED)',
    officialDomain: 'cred.club',
    officialVpaHandleSuffixes: ['@cred'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1614680376593-902f749f7ffc?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#111111',
    securityNotice: 'Cred coins cashback does not require merchant collect approval.',
    commonLureVectors: ['Cred Jackpot Claim', 'Cred Power Cash Voucher']
  },
  'Amazon Pay': {
    name: 'Amazon Pay India',
    officialDomain: 'amazon.in',
    officialVpaHandleSuffixes: ['@apl', '@rapl'],
    canonicalLogoUrl: 'https://images.unsplash.com/photo-1523474253046-8cd2748b5fd2?auto=format&fit=crop&w=120&h=120&q=80',
    colorTheme: '#ff9900',
    securityNotice: 'Amazon Pay refund is credited automatically without UPI collect confirmation.',
    commonLureVectors: ['Amazon Gift Card Won', 'Undelivered Package Fee']
  }
};
