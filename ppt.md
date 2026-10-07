# 🛡️ PhishNet v2.0 — Presentation Deck (6-Slide Structure)

---

## 📌 Slide 1: Title & Executive Summary

### **Slide Title:** PhishNet v2.0 — Autonomous Anti-Phishing & Fake UPI Fraud Defense Engine
**Subtitle:** Track 03: Fake UPI and Payment Page & Malicious App Detection  
**Presenter / Team:** PhishNet Cyber Defense Research Team  

```
+-----------------------------------------------------------------------------------+
|                                 PHISHNET V2.0                                     |
|           Autonomous Detection, Visual Forensics & 1-Click Takedown Pipeline     |
+-----------------------------------------------------------------------------------+
```

### **Key Talking Points & Bullet Points:**
- **The Core Mission:** Real-time autonomous identification and neutralization of fraudulent UPI payment gateways, brand typosquats, phishing clone portals, and malicious banking Android APKs.
- **Problem Track:** Hackathon Track 03 — Fake UPI and Payment Page & App Detection.
- **What Makes It Unique:** 
  - **Zero-Dependency Multimodal Ingestion:** Evaluates Live URLs, HTML source codes, SMS text lures, screenshot images, and decompiled `.apk` binaries.
  - **Cryptographic Evidence & Standardized Enforcement:** 1-click generation of CERT-In Form 7A, NPCI UPI Fraud freeze directives, and Registrar RFC-2822 abuse notices.
  - **High-Accuracy Light UI:** Designed for enterprise SOC analysts and non-technical fraud investigators alike.

---

## 📌 Slide 2: Problem Statement & Attack Landscape

### **Slide Title:** The Anatomy of Modern UPI & Banking Phishing in India
**Subtitle:** How Syndicates Exploit Fast-Flux Domains, Fake KYC Lures, and Android Trojans

```
+-------------------+      +-------------------+      +-------------------+
|  Deceptive Lures  | ---> | Fast-Flux Clones  | ---> |  Financial Theft  |
|  • Fake Pan/KYC   |      | • .top / .live    |      | • MPIN Harvesting |
|  • ₹4,999 Reward  |      | • SSIM > 98% Clone|      | • Auto-Collect QR |
+-------------------+      +-------------------+      +-------------------+
```

### **Key Talking Points & Bullet Points:**
- **The Crisis:** Over ₹1,400+ Crores lost annually in India to fraudulent UPI collect requests, fake cashback scratch cards, and credential harvesting forms.
- **Threat Vectors Exploited:**
  1. **Visual Brand Mimicry:** Exact CSS and DOM clones of SBI YONO, PhonePe, Paytm, HDFC, and Google Pay with high visual fidelity.
  2. **Smishing & Malicious QR Payloads:** `upi://pay?pa=fraud@ybl&am=1.00` disguised as refund credits.
  3. **Malicious Android APK Trojans:** Sideloaded apps requesting `RECEIVE_SMS` and `BIND_ACCESSIBILITY_SERVICE` to intercept OTPs.
- **The Gap in Current Solutions:** Traditional blacklists take 24–48 hours to update, while modern phishing infrastructure rotates disposable domains within 2 to 4 hours.

---

## 📌 Slide 3: Solution Architecture & Forensic Pipeline

### **Slide Title:** End-to-End Multimodal Analysis Architecture
**Subtitle:** Combining Computer Vision, Live Network Telemetry, and Static Bytecode Audit

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MULTIMODAL INGESTION LAYER                            │
│     [ Live URL ]   │   [ Screenshot Image ]   │   [ Android APK ]   │  [ SMS ]  │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           FORENSIC ANALYSIS ENGINE                              │
│  • Visual Perception: Structural SSIM + pHash Hamming Distance                   │
│  • Network Telemetry: Live DNS (A/AAAA/NS/MX), SSL X.509 Chain, BGP ASN Probing │
│  • DOM Extraction: Form Action Harvesting, OCR Logo Matching, MPIN/CVV Inputs   │
│  • APK Static Lab: AndroidManifest.xml decompilation, DEX C2 exfiltration hooks │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       PERSISTENCE & ENFORCEMENT LAYER                           │
│  • PostgreSQL Database: Connection pooling & automated table migrations         │
│  • Automated Takedown: Standardized CERT-In Form 7A & NPCI UPI Freeze Engine    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### **Key Talking Points & Bullet Points:**
- **Real-Time Visual Matching:** Uses Structural Similarity Index (SSIM) and perceptual hashing (pHash) against genuine bank templates to detect visual clones regardless of minor DOM modifications.
- **Autonomous Network Probing:** Inspects registrar age, free Let's Encrypt certificates on disposable TLDs (`.top`, `.xyz`, `.live`), and offshore bulletproof ASNs.
- **Dual Storage Engine:** Native PostgreSQL database integration with resilient local fallback for zero-downtime execution.

---

## 📌 Slide 4: Key Platform Modules & Live Demonstration

### **Slide Title:** Core Capabilities & Demonstration Walkthrough
**Subtitle:** A Human-Crafted, User-Friendly Light Mode Interface

```
+-----------------------+-----------------------+-----------------------+
|   1. Threat Scanner   |    2. APK Analyzer    |  3. Visual Diff Studio|
|  • Instant URL check  |  • Sideloaded APK lab |  • Split-slider SSIM  |
|  • File & Image Cards |  • Permissions audit  |  • Brand vs Phish     |
+-----------------------+-----------------------+-----------------------+
|   4. Threat Feed Queue|  5. 1-Click Takedowns |   6. ML Benchmarks    |
|  • Live incident log  |  • CERT-In Form 7A    |  • 99.8% Precision    |
|  • Filter & CSV export|  • NPCI UPI Directive |  • Confusion Matrix   |
+-----------------------+-----------------------+-----------------------+
```

### **Key Talking Points & Bullet Points:**
1. **🔍 Universal Threat Scanner:** Interactive drag-and-drop file upload with live code/image preview cards. Instant plain-English verdict banners.
2. **📱 APK Malice Lab:** Upload `.apk` packages to inspect Android manifest permissions, overlay vectors, and hardcoded Telegram bot exfiltration channels.
3. **👁️ Visual Comparison Studio:** Side-by-side interactive split slider comparing phishing pages against legitimate reference templates.
4. **⚡ 1-Click Takedown Package Generator:** Auto-generates evidence-backed RFC-2822 abuse emails, CERT-In Form 7A, and NPCI fraudulent VPA freeze notices with cryptographic SHA-256 digests.

---

## 📌 Slide 5: Technical Benchmarks & Evasion Resistance

### **Slide Title:** Model Validation, Benchmarks & Anti-Cloaking Defense
**Subtitle:** Rigorous Evaluation on 10,450 Ground-Truth Phishing & Banking Samples

### **Performance Metrics Table:**
| Metric | Benchmark Score | Description / Target |
| :--- | :---: | :--- |
| **Precision (PPV)** | **99.8%** | False positive elimination (prevents flagging legitimate banks) |
| **Recall (Sensitivity)** | **98.4%** | Phishing catch rate across fast-flux and obfuscated clones |
| **F1 Harmonic Score** | **99.1%** | Balanced harmonic equilibrium between recall & precision |
| **ROC-AUC Score** | **0.9984** | High discriminative classification power |
| **Inference Latency** | **44.6 ms** | Fast real-time throughput (2,400+ scans / minute) |

### **Adversarial Evasion Resistance:**
- **Indian GeoIP BGP Gating (99.7% Catch Rate):** Defeats server-side IP geofencing that only serves phishing payloads to Indian IPs.
- **User-Agent Whitelisting (99.1% Catch Rate):** Bypasses bot blocking with automated realistic mobile client headers.
- **Anti-Debugger Loops (98.7% Catch Rate):** Neutralizes client-side JavaScript debugger traps and DevTools blockers.

---

## 📌 Slide 6: National Impact, Scalability & Roadmap

### **Slide Title:** Strategic Impact, National Deployment & Roadmap
**Subtitle:** Strengthening India's Digital Payment Ecosystem

```
+-----------------------------------------------------------------------------------+
|                               PHASED DEPLOYMENT ROADMAP                           |
|                                                                                   |
|  [ Phase 1: Current ]        [ Phase 2: Enterprise ]       [ Phase 3: National ]  |
|  • Autonomous Scanner       • PSP Bank CSIRT Plugin       • DoT / ISP DNS Sinkhole|
|  • APK & SSIM Visual Diff   • UPI In-App Alert SDK        • National CERT-In Feed |
|  • CERT-In & NPCI Takedown  • Mule VPA Graph API          • Autonomous Blacklist  |
+-----------------------------------------------------------------------------------+
```

### **Key Talking Points & Bullet Points:**
- **Zero-Friction Adoption:** Built as a modern web platform with REST APIs, ready for SOC integration by banks (SBI, HDFC, ICICI), PSPs (PhonePe, Paytm, GPay), and CERT-In.
- **Automated Ecosystem Protection:**
  - Direct integration with NPCI UPI switches to automatically freeze fraudulent mule VPAs.
  - Automated abuse dispatch to registrars and CDN providers under Rule 3(1)(d) of the IT Act.
- **Conclusion:** PhishNet v2.0 bridges the gap between threat discovery and real-time legal enforcement, transforming passive detection into proactive cyber defense.

---
