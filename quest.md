# 🛡️ PhishNet v2.0 — Quick Technical Guide & Architecture Overview (`quest.md`)

> **Track 03:** Fake UPI and Payment Page & Malicious App Detection  
> **Platform:** PhishNet v2.0 Autonomous Anti-Phishing & Enforcement Pipeline

---

## ⚡ 1. Tech Stack Overview

| Layer | Technology Used | Purpose |
| :--- | :--- | :--- |
| **Frontend UI** | **React 18, TypeScript, Vite 5, Tailwind CSS** | Human-crafted Light Mode SOC interface, responsive cards, zero-clutter workflow. |
| **Icons & Visuals** | **Lucide React, Canvas API** | Crisp vector iconography, visual split slider, and screenshot pixel analysis. |
| **Backend API** | **Node.js, Express 5, TypeScript, TSX** | Asynchronous REST endpoints, live network probe orchestration, file stream handling. |
| **Database & Persistence** | **PostgreSQL (pg pool) + JSON Resilient Store** | Dual-mode storage for threats, campaign graphs, and CERT-In dispatch logs. |
| **Forensic Probing** | **Node DNS, TLS Sockets, Cheerio, Multer** | Live DNS (A/AAAA/NS/MX), SSL X.509 certificate chain audit, and DOM form parsing. |
| **Binary Decompilation** | **Static Android Manifest Parser & DEX Inspector** | Decodes `.apk` files, flags dangerous SMS/Overlay permissions, extracts C2 endpoints. |
| **Security & Hashes** | **Node Crypto (SHA-256), pHash, SSIM** | Perceptual image hashing, Structural Similarity Index, cryptographic evidence digests. |

---

## 🧭 2. Working of Every Feature (In Short)

### 1. 🔍 Universal Threat Scanner (`LiveScanner.tsx`)
- **What it does:** Accepts live URLs, raw HTML templates, SMS smishing texts, screenshot images, or APK files.
- **How it works:**
  1. Detects input modality automatically.
  2. For URLs: Queries live DNS, TLS certificate authority, and fetches page DOM via Cheerio to detect credential-stealing forms (`mpin`, `cvv`, `otp`).
  3. For Screenshots: Renders instant image preview and compares against real official banking templates (SBI, HDFC, Paytm, PhonePe) using perceptual hashing and SSIM visual fidelity.
  4. Returns a plain-English safety verdict (e.g. *SAFE 0.5%* vs *CRITICAL PHISH 98.4%*) with exact risk reasons.

---

### 2. 📱 APK Malice Lab (`ApkAnalyzer.tsx`)
- **What it does:** Sideloaded Android banking app auditor for detecting fake UPI helper APKs and trojans.
- **How it works:**
  1. Accepts `.apk` file uploads with drag-and-drop preview.
  2. Statically inspects `AndroidManifest.xml` for high-risk permissions (`RECEIVE_SMS`, `READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`).
  3. Scans compiled strings for hardcoded Telegram bot exfiltration webhooks and C2 server domains.
  4. Assigns a Trojan Risk Score (0–100%) and categorizes malware families.

---

### 3. 👁️ Visual Comparison Studio (`VisualSimilarityInspector.tsx`)
- **What it does:** Side-by-side interactive split-screen diff comparing suspected phishing portals against official bank baselines.
- **How it works:**
  1. Computes **Structural Similarity Index (SSIM)** and **pHash Hamming Distance**.
  2. Renders an interactive draggable split slider overlaying the suspicious page with the verified authentic template.
  3. Displays DOM structural edit distance, OCR logo match confidence, and font/color layout cloning scores.

---

### 4. 📋 Threat Operations & Incident Feed (`ThreatFeed.tsx`)
- **What it does:** Centralized SOC incident queue for security analysts to monitor, filter, and triage detected campaigns.
- **How it works:**
  1. Live searchable, filterable table with Brand filters, Severity badges, and Status workflows (`CONFIRMED_PHISH`, `IN_TAKEDOWN`, `TAKEN_DOWN`).
  2. 1-Click detail modal showing full network telemetry, host IP, ASN, harvested VPAs, and audit logs.
  3. 1-Click **Export to CSV / JSON** for SIEM and MISP threat intelligence ingestion.

---

### 5. ⚡ Automated 1-Click Takedown Dispatcher (`TakedownGenerator.tsx`)
- **What it does:** Generates legal, evidence-backed abuse notices and dispatches them across enforcement channels.
- **How it works:**
  1. **CERT-In Form 7A:** Formats formal incident report under Section 70B of the Indian IT Act.
  2. **NPCI UPI Fraud Directive:** Flags identified malicious VPAs (e.g., `fraud.kyc@paytm`) for immediate switch-level account freezes.
  3. **Registrar RFC-2822 Abuse Email:** Pre-composed DNS revocation notice with cURL proof and SHA-256 evidence digests.
  4. Records all sent takedowns in the persistent **Live Dispatch Ledger**.

---

### 6. 📊 Benchmark Performance & ML Evaluation (`BenchmarkEvaluation.tsx`)
- **What it does:** Transparent model validation on a ground-truth dataset of 10,450 labeled phishing vs genuine portals.
- **How it works:**
  1. Interactive **Decision Threshold Calibration Slider** ($\theta = 0.50$ to $0.95$).
  2. Displays real-time **Precision (99.8%)**, **Recall (98.4%)**, **F1 Score (99.1%)**, and **ROC-AUC (0.9984)**.
  3. Live Confusion Matrix ($N = 10,450$) and Evasion Resistance breakdown (GeoIP BGP gating, user-agent cloaking, anti-debugging traps).

---

## ⚙️ 3. How Things Work Under the Hood (System Flow)

```
[ User Input / File Upload ]
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. INGESTION & NORMALIZATION                                │
│    • Differentiates URLs vs Images vs Local Files vs Text   │
│    • Whitelist Verification (onlinesbi.sbi, hdfcbank.com...) │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. DUAL FORENSIC AUDIT                                      │
│    • Network Layer: Live DNS resolver + TLS socket probe    │
│    • Content Layer: Cheerio DOM form parser + SSIM visual   │
│    • Binary Layer: Android Manifest & DEX bytecode check    │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. MULTI-FACTOR HEURISTIC SCORING                           │
│    • Overall Risk Score = Weighted SSIM + DOM + Infra + UPI │
│    • Extracts Genuine IOCs (UPI Handles & Phone Numbers)    │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. PERSISTENCE & LEGAL ENFORCEMENT                          │
│    • Persists threat record to PostgreSQL / Resilient Store │
│    • 1-Click CERT-In Form 7A & NPCI Takedown Dispatch       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 4. How to Run Locally

```bash
# 1. Install dependencies
npm install

# 2. Configure Environment (Optional - Postgres is auto-detected)
cp .env.example .env

# 3. Start Backend API and Frontend Dev Server concurrently
npm run dev

# 4. Open in browser
http://localhost:5173
```
