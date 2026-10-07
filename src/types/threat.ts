export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type ThreatStatus =
  | "INVESTIGATING"
  | "CONFIRMED_PHISH"
  | "TAKEDOWN_DISPATCHED"
  | "TAKEN_DOWN"
  | "MONITORING"
  | "FALSE_POSITIVE";
export type TargetBrand =
  | "PhonePe"
  | "Paytm"
  | "Google Pay"
  | "SBI YONO"
  | "HDFC Bank"
  | "ICICI iMobile"
  | "BHIM UPI"
  | "Axis Bank"
  | "Cred"
  | "Amazon Pay";

export interface ThreatItem {
  id: string;
  url: string;
  domain: string;
  targetBrand: TargetBrand;
  threatType:
    | "FAKE_UPI_PORTAL"
    | "SMISHING_LURE"
    | "MALICIOUS_APK"
    | "FAKE_PAYMENT_GATEWAY"
    | "QR_PHISHING";
  discoverySource:
    | "CT_LOGS"
    | "SMS_STREAM"
    | "USER_REPORT"
    | "BANK_CSIRT_INTEL"
    | "CERT_IN_FEED";
  discoveryTimestamp: string;
  severity: SeverityLevel;
  status: ThreatStatus;

  // Similarity Engine Scores
  similarityScore: number; // 0 - 100
  pHashDistance: number; // 0 - 64 (lower is closer match)
  structuralSSIM: number; // 0.0 - 1.0
  domEditDistance: number; // 0.0 - 1.0
  logoConfidence: number; // 0 - 100%

  // Infrastructure Telemetry
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  countryCode: string;
  registrar: string;
  sslIssuer: string;
  sslSerial: string;
  dnsNameservers: string[];

  // Payment / Fraud vector details
  extractedUPI_VPA?: string[];
  extractedPhoneNumbers?: string[];
  extractedBankAccounts?: string[];
  qrCodePayload?: string;
  apkPackageName?: string;
  apkSha256?: string;

  // Campaign Attribution
  campaignId: string;
  campaignName: string;
  threatActorSyndicate: string;

  // Evasion Tactics Detected
  evasionTactics: {
    antiBotGating: boolean;
    canvasFingerprinting: boolean;
    geoFencingIndiaOnly: boolean;
    userAgentFiltering: boolean;
    devtoolsBlocker: boolean;
    dynamicDomRedirection: boolean;
    fakeSslBadge: boolean;
  };

  // Visual Evidence
  screenshotUrl: string;
  genuineReferenceUrl: string;
  evidenceHash: string; // SHA-256 digest

  // Notes / Timeline
  timeline: {
    time: string;
    event: string;
    actor: string;
  }[];
}

export interface CampaignCluster {
  id: string;
  name: string;
  syndicate: string;
  riskScore: number;
  threatLevel: SeverityLevel;
  firstSeen: string;
  lastSeen: string;
  activeNodesCount: number;
  domainsCount: number;
  ipsCount: number;
  vpasCount: number;
  targetedBrands: TargetBrand[];
  financialLossEstimateINR: string;
  takedownSuccessRate: number; // percentage
  status: "ACTIVE" | "DISRUPTED" | "MONITORED";
}

export interface GraphNode {
  id: string;
  label: string;
  type:
    | "DOMAIN"
    | "IP"
    | "ASN"
    | "UPI_VPA"
    | "PHONE"
    | "APK"
    | "SSL_CERT"
    | "CAMPAIGN";
  severity?: SeverityLevel;
  campaignId?: string;
  details?: Record<string, any>;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  relationship:
    | "HOSTED_ON"
    | "ROUTES_THROUGH"
    | "COLLECTS_VIA"
    | "ASSOCIATED_PHONE"
    | "DISTRIBUTES_APK"
    | "SHARES_CERT"
    | "MEMBER_OF";
  confidence: number;
}

export interface CTLogEntry {
  id: string;
  domain: string;
  issuer: string;
  timestamp: string;
  matchedBrand?: TargetBrand;
  riskScore: number;
  isFlagged: boolean;
  fingerprint: string;
}

export interface ModelMetrics {
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
  falsePositiveRate: number;
  aucRoc: number;
  averageLatencyMs: number;
  totalTestedSamples: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
}
