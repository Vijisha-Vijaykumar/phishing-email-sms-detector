# PhishGuard AI — Complete Project Report
### Explainable & Robust Phishing Detection for Email, SMS, URL & Attachments
**Version:** 1.0.0 · **Tagline:** *Detect before you click.* · **Date:** October 2026

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [System Architecture](#3-system-architecture)
4. [Backend Pipeline — Inference Engine](#4-backend-pipeline--inference-engine)
5. [ML Model Lineage (A → C)](#5-ml-model-lineage)
6. [Rule Engine & Deterministic Layer](#6-rule-engine--deterministic-layer)
7. [Phishing Intent Fingerprint System](#7-phishing-intent-fingerprint-system)
8. [Named Entity Recognition (NER)](#8-named-entity-recognition)
9. [PII Masking & Privacy Enclave](#9-pii-masking--privacy-enclave)
10. [URL Analysis Engine](#10-url-analysis-engine)
11. [Attachment Scanner](#11-attachment-scanner)
12. [OSINT & Web Intelligence Engine](#12-osint--web-intelligence-engine)
13. [XAI — Explainable AI Guardrail](#13-xai--explainable-ai-guardrail)
14. [API Endpoints](#14-api-endpoints)
15. [Frontend — Cyberpunk HUD Interface](#15-frontend--cyberpunk-hud-interface)
16. [Data Engineering Pipeline](#16-data-engineering-pipeline)
17. [Training Scripts](#17-training-scripts)
18. [Evaluation & Research Metrics](#18-evaluation--research-metrics)
19. [Test Suite](#19-test-suite)
20. [Security & Privacy Design](#20-security--privacy-design)
21. [Tech Stack](#21-tech-stack)
22. [Project File Structure](#22-project-file-structure)
23. [Key Design Decisions](#23-key-design-decisions)
24. [Limitations & Ethical Disclaimer](#24-limitations--ethical-disclaimer)

---

## 1. Project Overview

**PhishGuard AI** is a fully local, privacy-preserving, explainable AI system for detecting phishing threats across four attack surfaces:

| Channel | What it analyzes |
|---|---|
| SMS | Short message body + sender ID / MSISDN |
| Email | Full email body + subject + sender address |
| URL | Standalone URL heuristics + OSINT reputation |
| Attachment | Static binary analysis — PDF, Office, ZIP, PE |

> [!IMPORTANT]
> **No external LLM is called at any stage.** All predictions come from trained scikit-learn pipelines. No message content is transmitted to third-party cloud APIs. The only optional live network call is to the URLhaus (abuse.ch) threat database — querying only public domain names, never user message content.

---

## 2. Problem Statement

Phishing attacks remain the #1 initial access vector globally. Existing solutions suffer from:

- **Opacity** — black-box neural models give no actionable evidence
- **Privacy risk** — cloud-based scanning transmits sensitive user messages
- **Single-channel scope** — most tools cover only email or only URLs
- **Code-mixed blindness** — Indian SMS phishing frequently mixes Hindi/English (Hinglish)
- **No social engineering fingerprinting** — they flag URLs but miss the psychological manipulation layer

PhishGuard AI addresses all five gaps in a single integrated system.

---

## 3. System Architecture

```
FRONTEND (React + Vite, port 5173)
  SMS · EMAIL · URL · ATTACHMENT  →  Cyberpunk HUD Dashboard
           |
           | HTTP
           v
FASTAPI BACKEND (port 8000)
  Input → PII Masking → NER → Rule Engine → URL Heuristics →
  OSINT Intel → Rule Feature Vector → ML Prediction →
  Fingerprint → XAI Explanation → Safety Advice → JSON Response
           |              |                |
       ML Models    Rule Engine      Reputation
       (pickle)     (432 LOC)       Analyzer
       A/A2/B/C   deterministic    (OSINT+Live)
```

**Runtime stack:**
- **Backend:** Python 3.11 · FastAPI · Uvicorn (with `--reload`)
- **Frontend:** React 18 · Vite · Vanilla CSS (no Tailwind)
- **ML:** scikit-learn · sentence-transformers · scipy · numpy
- **No database** — all inference is stateless except in-memory repeat-check cache

---

## 4. Backend Pipeline — Inference Engine

**File:** [`predict.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/routes/predict.py) (358 lines)

Every `/predict` request runs through **12 sequential pipeline stages**:

| Stage | Module | What happens |
|---|---|---|
| **1. Input Validation** | Pydantic `PredictRequest` | Channel, text length, subject, sender validated |
| **2. PII Masking** | `pii_masker.sanitize_and_mask()` | Phones, emails, cards, TXN refs replaced with `[PHONE]` etc. before ML |
| **3. NER Extraction** | `ner_extractor.extract_entities()` | Banks, govt bodies, URLs, phone numbers, amounts, dates extracted |
| **4. Rule Analysis** | `rule_engine.analyze_text()` + `analyze_sender()` | Urgency, threat type, authority, fear, reward, pressure, OTP cues scored |
| **5. URL Analysis** | `url_analyzer.analyze_url_extended()` | Each extracted URL analyzed for 9 heuristic checks |
| **5b. OSINT Intel** | `reputation_analyzer.analyze_web_reputation()` | Domains checked against 7 threat intelligence sources |
| **6. Rule Feature Vector** | `rule_features.build_rule_feature_vector()` | Deterministic signals compiled into feature vector D_rules |
| **7. ML Prediction** | `predictor.predict()` | Best available model (C > B > A2 > A) runs inference |
| **8. Intent Fingerprint** | `predictor.predict_fingerprint()` | 4D social engineering fingerprint predicted (never uses gold labels) |
| **9. XAI Explanation** | `xai_explainer.build_explanation()` | Deterministic natural-language rationale built from detected cues |
| **10. Safety Advice** | `xai_explainer.build_safety_advice_structured()` | Risk-appropriate action items generated |
| **11. Evidence List** | `rule_engine.build_evidence_list()` | All contributing signals compiled into evidence array |
| **12. Repeat Check** | `repeat_check.check_and_increment()` | Session-level message deduplication check |

---

## 5. ML Model Lineage

**Config:** [`config.yaml`](file:///c:/Users/Admin/Downloads/cyberhack/config.yaml) · **Predictor:** [`predictor.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/predictor.py)

Four models form an **ordered fallback hierarchy** — the best trained model available on disk is used automatically:

### Model A — Baseline Lexical
- **Architecture:** Word TF-IDF (unigrams + bigrams, 5,000 features) → Logistic Regression
- **Purpose:** Establishes upper-bound for pure lexical approaches
- **Artifact:** `models/trained/model_a_baseline.pkl`

### Model A2 — Robust Lexical
- **Architecture:** Word TF-IDF (4,000 features) + Character n-gram TF-IDF (char_wb, 2-5-gram, 8,000 features) → LR
- **Key improvement:** Character n-grams capture sub-word invariants in Romanized Hindi (e.g. *karein* vs *karen* vs *kariye*) — critical for Indian SMS phishing
- **Artifact:** `models/trained/model_a2_robust_lexical.pkl`

### Model B — Semantic (Multilingual)
- **Architecture:** `paraphrase-multilingual-MiniLM-L12-v2` frozen embeddings → Logistic Regression
- **Key improvement:** Language-agnostic dense representations handle code-mixed Hinglish
- **Artifact:** `models/trained/model_b_semantic.pkl`

### Model C — Proposed (Semantic + Intent Fingerprint)
- **Architecture:** MiniLM-L12 embeddings + D_rules (rule feature vector) + **predicted** 4D intent fingerprint → LR
- **Critical design:** Fingerprint features are **always predicted at inference time** — never uses gold labels, preventing any label leakage
- **Training:** Out-of-fold (OOF) 5-fold cross-validation to generate clean fingerprint features for training
- **Artifact:** `models/trained/model_c_proposed.pkl`

**Model hierarchy at runtime (best available wins):**
```
Model C  →  Model B  →  Model A2  →  Model A
```

### Thresholds (from `config.yaml`)
```yaml
high_risk_threshold:  0.65   # P(phishing) >= 0.65 → High-risk
suspicious_threshold: 0.35   # P(phishing) >= 0.35 → Suspicious
hard_otp_override:    true   # OTP share request always escalates to High-risk
```

---

## 6. Rule Engine & Deterministic Layer

**File:** [`rule_engine.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/rules/rule_engine.py) (432 lines)

The rule engine runs **entirely deterministically** — zero ML, zero LLM. It compiles Python `re.compile()` patterns loaded once at startup.

### Signals Detected

| Signal Category | Patterns Matched |
|---|---|
| **Urgency** | immediately, urgent, within 24 hours, last warning, act now, deadline, no time, final notice... |
| **Threat Types** | Account suspension · Service disconnection · Financial loss · SIM deactivation · Legal action · Parcel/delivery hold |
| **Authority Impersonation** | SBI, HDFC, ICICI, RBI, TRAI, police, court, judiciary, Amazon, Microsoft, Paytm, GPay, UIDAI... |
| **Credential Requests** | OTP, PIN, password, CVV, card number, Aadhaar, PAN, net banking, IFSC... |
| **Payment Requests** | Pay, transfer, UPI, NEFT, RTGS, IMPS, cashback, refund claim, customs fee... |
| **Fear Language** | Suspend, block, deactivate, terminate, penalty, fine, arrest, unauthorized, illegal... |
| **Reward Lures** | Prize, win, lottery, reward, cashback, bonus, lucky draw, gift card... |
| **Pressure Tactics** | Deadline, expiry, limited time, only X left, act before... |
| **OTP Share Instruction** | Share OTP, enter OTP received, don't tell anyone your OTP (reverse-psychology detection) |
| **Sender Analysis** | Free webmail vs org domain · domain mismatch · suspicious format |

**Rule Feature Vector (D_rules):** `rule_features.py` encodes all rule signals into a dense float vector that is concatenated with ML embeddings for Model C.

---

## 7. Phishing Intent Fingerprint System

**Config:** `config.yaml` (fingerprint section)

The **4D Social Engineering Fingerprint** characterizes *how* an attacker manipulates the victim — not just *whether* a message is phishing.

| Dimension | Classes |
|---|---|
| **Threat Vector** | None · Account suspension · Service disconnection · Financial loss · SIM deactivation · Legal action · Parcel/Delivery hold · Other |
| **Urgency Level** | Low · Medium · High |
| **Requested Action** | None · Pay · Click link · Verify identity · Share credential · Call number · Approve transaction · Reply/contact |
| **Demanded Asset** | None · Credential · Payment · Both |

**Training integrity:** The fingerprint classifier is trained using **out-of-fold predictions** only — the model never sees its own training labels during feature generation for Model C, preventing leakage.

---

## 8. Named Entity Recognition

**File:** [`ner_extractor.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/ner_extractor.py) (115 lines)

Fully deterministic regex-based entity extraction — no external NLP API.

| Entity Type | Examples |
|---|---|
| **Banks / Financial** | SBI, HDFC, ICICI, Kotak, Axis, Paytm, PhonePe, PayPal, Razorpay |
| **Government Bodies** | RBI, SEBI, IRDAI, TRAI, UIDAI, EPFO, Income Tax, CBI, ED |
| **Tech / E-commerce** | Amazon, Flipkart, Microsoft, Apple, Google, Airtel, Jio, DHL, India Post |
| **URLs** | All HTTP/HTTPS links and `www.` prefixed URLs |
| **Phone Numbers** | Indian mobile numbers (+91 prefix, 6-9 start, 10 digits) |
| **Monetary Amounts** | Rs. 850, 12,500 rupees, INR amounts |
| **Dates / Deadlines** | "10 October", "today", "tonight", "within 24 hours" |
| **Structural Refs** | Account number reference (structure only, never raw value) |

---

## 9. PII Masking & Privacy Enclave

**File:** [`pii_masker.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/pii_masker.py) (59 lines)

Before **any ML inference**, the message is sanitized:

| PII Type | Replaced with |
|---|---|
| Phone numbers | `[PHONE]` |
| Email addresses | `[EMAIL]` |
| 16-digit card numbers | `[CARD]` |
| Account/long digit strings | `[ACCOUNT]` |
| Transaction references | `[TXN_REF]` |

> [!NOTE]
> OTPs are deliberately **not** masked — their presence is a primary phishing signal the model must see. Raw PII summaries (counts only, never values) are returned in the API response for UI display.

---

## 10. URL Analysis Engine

**File:** [`url_analyzer.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/url_analyzer.py) (220 lines)

Nine-layer heuristic inspection of every URL found in a message, plus standalone URL scanning:

| Check | Detection Logic |
|---|---|
| **1. IP-based URL** | Numeric IP address instead of domain name |
| **2. Unencrypted HTTP** | URL starts with `http://` instead of `https://` |
| **3. URL Shortener** | Domain matches 20+ known shorteners (bit.ly, tinyurl, t.co, goo.gl...) |
| **4. Suspicious TLD** | Ends with .xyz, .top, .site, .biz, .pw, .tk, .cf, .click, .icu... (23 TLDs) |
| **5. Punycode / IDN** | Contains `xn--` (homograph attack potential) |
| **6. Typosquatting** | Domain contains lookalike strings (paypa1, amaz0n, app1e, micros0ft, netf1ix...) |
| **7. Subdomain injection** | Known brand name appears as subdomain of unrelated domain |
| **8. Path analysis** | Long random strings · Heavily URL-encoded payloads · Banking keywords (login, kyc, verify, otp) |
| **9. Trusted-domain lookup** | 46 trusted canonical domains checked (supporting evidence only) |

**Standalone URL scanner** (URL channel) also runs the full OSINT reputation check and returns `web_intel` in the response.

---

## 11. Attachment Scanner

**File:** [`attachment_analyzer.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/attachment_analyzer.py) (513 lines)

Static-only analysis — files are **never executed**, macros are **never run**.

### File Types Supported
`PDF · DOC/DOCX · XLS/XLSX · PPT/PPTX · ZIP · RAR · EXE · DLL · BAT · PS1`

### Analysis Performed

| Check | What it detects |
|---|---|
| **Magic byte detection** | True file type from binary header (cannot be spoofed by extension) |
| **Shannon entropy** | High entropy (>7.0) indicates packing, encryption, or obfuscation |
| **Macro detection** | OLE2 compound documents parsed for VBA macro presence |
| **Suspicious macros** | Known dangerous VBA patterns: Shell, CreateObject, WScript, PowerShell |
| **JavaScript in PDF** | `/JS`, `/JavaScript` dictionary keys in PDF stream |
| **Embedded URL extraction** | All URLs extracted from file content for secondary URL analysis |
| **Archive inspection** | ZIP/RAR contents listed; bomb detection (max 100MB uncompressed, 100x ratio, 3-level depth) |
| **Dangerous extensions** | 36 dangerous extensions detected inside archives (.exe, .bat, .ps1, .vbs, .hta, .lnk...) |
| **PE binary analysis** | Suspicious Win32 API imports (process injection, network downloader, keylogger, anti-debug) |
| **File size validation** | Max 25MB upload, streaming chunked read |

**Quarantine:** Every uploaded file is written to a secure temporary directory and deleted immediately after analysis — never persisted.

```
Upload → Quarantine (tempfile) → Static Parse → Delete → Results
                 NEVER executed, NEVER stored
```

---

## 12. OSINT & Web Intelligence Engine

**File:** [`reputation_analyzer.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/reputation_analyzer.py) (490+ lines)

The OSINT engine performs **multi-source intelligence correlation** on extracted domains, senders, and organizations — querying only public entity names, never user message content.

### Intelligence Sources (7 sources)

| Source | What is checked |
|---|---|
| **Official Brand Registry** | 17 brands (HDFC, SBI, ICICI, Axis, Kotak, Paytm, PhonePe, PayPal, Chase, Amazon, Microsoft, Apple, Netflix, India Post, RBI, Google, IRS) → canonical domain verification |
| **Scam Advisory Bulletins** | 14 pattern categories: Banking KYC, PayPal, Chase, Parcel, Electricity, Lottery, Amazon, Microsoft, IRS, Job, Crypto, RBI, UPI, Insurance scams |
| **Social Media Intelligence** | 8 signal categories correlated against Twitter/X, Reddit r/Scams, WhatsApp, LinkedIn, Instagram, Telegram reports |
| **URLhaus API (abuse.ch)** | Live query to URLhaus database (1M+ confirmed malicious URLs); 2-second timeout; domain only submitted |
| **TLD Abuse Statistics** | 15 high-risk TLDs cross-referenced against URLhaus/APWG bulk phishing data |
| **Dynamic DNS Detection** | 8 DDNS providers (DuckDNS, No-IP, DDNS.net, Hopto, etc.) flagged per SANS ISC advisory |
| **Free Hosting Abuse** | 12 platforms (GitHub Pages, Netlify, Vercel, Wix, Weebly, Glitch, Repl.co...) flagged per APWG eCrime data |

### Risk Elevation Logic
```python
# In predict.py — OSINT can escalate ML predictions
if web_intel["is_known_scam"] or (web_intel["impersonation_alerts"] and risk == "Genuine"):
    risk = "High-risk" if web_intel["is_known_scam"] else "Suspicious"
```

---

## 13. XAI — Explainable AI Guardrail

**File:** [`xai_explainer.py`](file:///c:/Users/Admin/Downloads/cyberhack/backend/app/services/xai_explainer.py) (214 lines)

Deterministic, template-based explanation — **no LLM text generation**, ever.

Each detected cue maps to a predefined explanation template:

| Detected | Template Used |
|---|---|
| Urgency = High | "This message creates strong time pressure, a classic phishing technique to prevent careful thinking." |
| OTP share request | "It actively requests that you share an OTP — a definitive phishing indicator." |
| IP-based URL | "It contains a link pointing to a raw IP address — legitimate services do not do this." |
| Typosquatting | "The link uses a domain that closely resembles a legitimate brand name (typosquatting)." |
| Free webmail sender | "The message arrives from a free webmail provider instead of an official domain." |
| Brand impersonation | "OSINT Intelligence Alert: [impersonation finding appended]" |

### Safety Advice Gate
Risk-appropriate structured action list:
- **High-risk:** Do not click, report to CERT-In, contact institution through official channels only
- **Suspicious:** Verify independently, check domain manually, do not share credentials
- **Genuine:** Standard caution, verify SSL certificate

---

## 14. API Endpoints

**Base URL:** `http://localhost:8000`

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Root — project info & link map |
| `GET` | `/health` | Health check |
| `GET` | `/docs` | Swagger UI (auto-generated) |
| `POST` | `/predict` | **Main inference endpoint** — full 12-stage pipeline |
| `POST` | `/fingerprint` | Returns 4D phishing intent fingerprint only |
| `POST` | `/extract` | Extracts entities from message |
| `POST` | `/url-check` | Single URL heuristic analysis |
| `POST` | `/sender-check` | Sender identifier analysis |
| `POST` | `/repeat-check` | Session repeat message check |
| `POST` | `/web-intel` | Standalone OSINT reputation query |
| `GET` | `/research/metrics` | Model evaluation results |
| `POST` | `/analyze-attachment` | Attachment static analysis |
| `POST` | `/analyze-url` | Standalone URL analysis + OSINT |
| `POST` | `/api/attachment/analyze-attachment` | Attachment (prefixed proxy path) |
| `POST` | `/api/attachment/analyze-url` | URL analysis (prefixed proxy path) |
| `GET` | `/samples` | Demo message samples |

---

## 15. Frontend — Cyberpunk HUD Interface

**Framework:** React 18 + Vite · **Styling:** Vanilla CSS (1,600 lines) · **Port:** 5173

### Design System
- **Theme:** Neon Cyberpunk HUD — deep void obsidian + electric cyan + neon violet + matrix lime + crimson threat
- **Typography:** Orbitron (display) · Space Grotesk (body) · Syne (accents) · IBM Plex Mono (code/telemetry)
- **Effects:** Glassmorphism cards · Radar scanner animations · Neon glow borders · Micro-animations on hover

### Pages / Tabs

| Tab | Component | Content |
|---|---|---|
| **Detector** | `DetectorTab.jsx` (81KB) | Main 4-channel scanner with full result dashboard |
| **Methodology** | `MethodologyTab.jsx` | Model lineage, fingerprint system, pipeline explanation |
| **Research** | `ResearchTab.jsx` | Live model metrics, evaluation charts |
| **Privacy** | `PrivacyTab.jsx` | Privacy guarantees, PII masking explanation |
| **Limitations** | `LimitationsTab.jsx` | Honest scope & capability limits |

### 4 Scan Channels (PORT_01 to PORT_04)

**PORT_01 — SMS Channel**
- Sender ID / MSISDN field + Message body textarea
- Demo presets: High-risk / Suspicious / Genuine
- Full results dashboard

**PORT_02 — Email Channel**
- Subject + Sender email + Body textarea
- Demo presets: High-risk email / Genuine AWS billing email

**PORT_03 — URL Channel (Standalone)**
- Single URL input with clear button, Enter key to scan
- 6 demo presets (typosquatting, IP-based, shortener, subdomain injection, official bank, AWS)
- Heuristic inspection badge list

**PORT_04 — Attachment Channel**
- Drag-and-drop file zone + browse button
- Supports: PDF · DOC/DOCX · XLS/XLSX · PPT · ZIP · RAR · EXE · DLL · PS1
- Max 25MB · No execution · Sandboxed quarantine

### Result Dashboard Components

| Panel | What it shows |
|---|---|
| **Risk Header** | Risk level badge · Confidence % · Model used · Latency ms |
| **Disclaimer** | Mandatory model-based assessment disclaimer |
| **XAI Reasoning Matrix** | Full natural-language explanation from deterministic XAI |
| **Phishing Intent Fingerprint** | 4D grid: Threat Vector · Urgency · Requested Action · Demanded Asset |
| **Cognitive Social Engineering Vectors** | Badges: OTP Harvesting · Credential Targeted · Payment Demand · Fear Tactic · Authority Impersonation · Pressure · Reward Lure |
| **Threat Indicators** | Full evidence list from rule engine + URL + sender + OSINT |
| **Tactical Defense Protocol** | Risk-appropriate structured safety advice |
| **Inspected URL Targets** | Per-URL: HTTPS/HTTP badge · flags · trust notes · "Scan Alone →" button |
| **Originator Analysis** | Sender format type · format classification · mismatch indicators |
| **Extracted Entities & Privacy Enclave** | PII masking summary · Banks · Government bodies · Orgs · Amounts · Dates |
| **Web Intelligence / OSINT Panel** | Reputation status · Threat score /100 · Brand impersonation alerts · Scam bulletins · Social media signals · URLhaus threat feed · Sources queried |

---

## 16. Data Engineering Pipeline

**Directory:** `scripts/` · **Data:** `data/`

### Dataset Sources
| Dataset | Description |
|---|---|
| UCI SMS Spam | Classic SMS spam/ham baseline |
| Mishra-Soni | Indian SMS phishing corpus |
| Enron Email | Legitimate corporate email corpus |
| Email Phishing | Phishing email corpus |
| URL Dataset | Malicious/benign URL corpus |
| Custom Robustness Suite | Hand-crafted adversarial test vectors (31KB) |

### Data Pipeline Scripts

| Script | Purpose |
|---|---|
| `download_datasets.py` | Downloads and extracts public datasets |
| `clean_data.py` | Normalizes text, removes duplicates, standardizes labels, handles encoding |
| `curate_research_data.py` | Research-grade curation with quality filtering |
| `build_custom_dataset.py` | Builds the hand-crafted adversarial robustness suite |
| `check_leakage.py` | Detects train/test overlap and label leakage |
| `check_overlap.py` | Cross-dataset duplicate detection |
| `audit_datasets.py` | Generates dataset quality audit report |

### Processed Data Format
- **Train/Test split:** 80/20 (seed=42)
- **Format:** Parquet (columnar, efficient)
- **K-Fold:** 5-fold GroupKFold for out-of-fold fingerprint generation

---

## 17. Training Scripts

| Script | Model trained | Key technique |
|---|---|---|
| `train_baseline.py` | Model A | Word TF-IDF (1-2gram, 5k) + LR |
| `train_robust_lexical.py` | Model A2 | Word + Char n-gram TF-IDF + LR |
| `train_semantic.py` | Model B | MiniLM-L12-v2 frozen embeddings + LR |
| `train_fingerprint.py` | Fingerprint classifiers | 4 separate LR classifiers per fingerprint dimension |
| `evaluate.py` | All models | Cross-validated evaluation, classification report, confusion matrix |

All artifacts saved to `models/trained/` as `.pkl` files.

---

## 18. Evaluation & Research Metrics

**Endpoint:** `GET /research/metrics` · **Results:** `reports/results/`

Metrics computed per model:
- Classification report (precision, recall, F1 per class)
- Accuracy & macro-averaged F1
- Confusion matrix
- Out-of-fold cross-validation scores

Results are viewable live in the **Research tab** of the frontend.

---

## 19. Test Suite

**Directory:** `tests/`

| Test File | What it tests |
|---|---|
| `test_api.py` (13.8KB) | Full API integration tests — all endpoints, edge cases, error handling |
| `test_rule_engine.py` | Deterministic rule engine correctness, urgency detection, threat patterns |
| `test_extractor.py` | NER extraction accuracy — URLs, phones, amounts, entities |
| `test_attachment.py` | Attachment analyzer — file type detection, entropy, macro detection |
| `test_reputation.py` | OSINT reputation analyzer — brand impersonation, scam patterns |
| `test_leakage.py` | Confirms zero train/test data leakage |

Run with: `pytest tests/ -v`

---

## 20. Security & Privacy Design

### Privacy Guarantees
1. **No cloud LLM transmission** — zero message content leaves the local machine via ML
2. **PII masked before inference** — phones, emails, cards replaced with structural tokens
3. **OSINT queries are domain-only** — only public hostnames submitted to URLhaus API, never message bodies
4. **No persistent storage** — all inference is stateless; attachment files deleted immediately
5. **Repeat check is session-local** — uses in-memory hash, never persisted to disk or database

### Attachment Security
- Files never executed · Macros never triggered
- Shell commands never constructed from user input
- Quarantine directory cleaned immediately post-analysis
- ZIP bomb protection (100MB limit, 100x ratio, 3-level depth)

### API Security
- Pydantic input validation on every endpoint
- File size streaming validation (rejects oversized payloads before writing)
- CORS restricted to `localhost:5173` and `localhost:3000`

---

## 21. Tech Stack

### Backend
| Component | Technology |
|---|---|
| Framework | FastAPI 0.100+ |
| ASGI Server | Uvicorn + `--reload` |
| ML | scikit-learn · scipy · numpy |
| NLP | sentence-transformers (paraphrase-multilingual-MiniLM-L12-v2) |
| Data | pandas · pyarrow (parquet) |
| Serialization | pickle (model artifacts) |
| HTTP client | `urllib.request` (stdlib — no heavy dependencies for OSINT) |
| Config | PyYAML |
| Testing | pytest |

### Frontend
| Component | Technology |
|---|---|
| Framework | React 18 |
| Build tool | Vite |
| Styling | Vanilla CSS (1,600 LOC custom design system) |
| Icons | Lucide React |
| HTTP | Native `fetch` API |
| Fonts | Google Fonts (Orbitron · Space Grotesk · Syne · IBM Plex Mono) |

---

## 22. Project File Structure

```
cyberhack/
├── config.yaml                     Central experiment config
├── backend/
│   └── app/
│       ├── main.py                 FastAPI app entry + CORS + router mounts
│       ├── routes/
│       │   ├── predict.py          Main /predict pipeline (12 stages, 358 lines)
│       │   ├── attachment.py       /analyze-attachment + /analyze-url routes
│       │   └── samples.py          Demo samples endpoint
│       ├── rules/
│       │   └── rule_engine.py      Deterministic rule engine (432 lines)
│       └── services/
│           ├── predictor.py        ML model loader & inference (272 lines)
│           ├── ner_extractor.py    Named entity recognition (115 lines)
│           ├── pii_masker.py       PII tokenization & masking (59 lines)
│           ├── url_analyzer.py     9-check URL heuristics (220 lines)
│           ├── attachment_analyzer.py  Static file analysis (513 lines)
│           ├── reputation_analyzer.py  OSINT & web intel (490+ lines)
│           ├── rule_features.py    D_rules feature vector builder
│           ├── xai_explainer.py    Deterministic XAI engine (214 lines)
│           └── repeat_check.py     Session deduplication
├── frontend/
│   ├── src/
│   │   ├── index.css               Cyberpunk design system (1,600 lines)
│   │   ├── App.jsx                 Tab routing & layout
│   │   └── components/
│   │       ├── DetectorTab.jsx     Main scanner (81KB — all 4 channels)
│   │       ├── Header.jsx          Navigation header
│   │       ├── MethodologyTab.jsx  Research methodology
│   │       ├── ResearchTab.jsx     Live metrics dashboard
│   │       ├── PrivacyTab.jsx      Privacy documentation
│   │       └── LimitationsTab.jsx  Honest limitations
│   └── vite.config.js              Proxy: /api/* → localhost:8000
├── scripts/
│   ├── build_custom_dataset.py     Adversarial test suite builder
│   ├── train_baseline.py           Model A training
│   ├── train_robust_lexical.py     Model A2 training
│   ├── train_semantic.py           Model B training
│   ├── train_fingerprint.py        Fingerprint classifiers training
│   ├── evaluate.py                 Cross-validated evaluation
│   ├── clean_data.py               Data normalization
│   ├── curate_research_data.py     Research curation
│   ├── download_datasets.py        Dataset downloader
│   ├── check_leakage.py            Leakage detection
│   ├── check_overlap.py            Cross-dataset overlap detection
│   └── audit_datasets.py           Quality audit report generator
├── data/
│   ├── raw/                        Original downloaded datasets
│   ├── interim/                    Cleaned intermediate files
│   ├── processed/                  train.parquet + test.parquet
│   ├── custom/                     robustness_suite.json
│   └── audit/                      Dataset audit reports
├── models/
│   └── trained/                    .pkl model artifacts (A, A2, B, C, fingerprint)
├── reports/
│   └── results/                    model_*_results.json evaluation outputs
└── tests/
    ├── test_api.py                 Integration tests (13.8KB)
    ├── test_rule_engine.py         Rule correctness tests
    ├── test_extractor.py           NER tests
    ├── test_attachment.py          File analyzer tests
    ├── test_reputation.py          OSINT tests
    └── test_leakage.py             Data leakage tests
```

---

## 23. Key Design Decisions

### 1. No LLM at Inference Time
External LLMs are expensive, slow, privacy-risky, and non-deterministic. PhishGuard AI uses only pre-trained, local scikit-learn models. This makes the system privacy-preserving, deterministic, auditable, fast (<200ms typical), and offline-capable.

### 2. Explainability by Construction
The XAI layer uses **deterministic templates** mapped to detected cues — not post-hoc attribution (like LIME/SHAP). Every explanation is directly tied to evidence actually found, human-readable without ML expertise, and legally defensible.

### 3. OOF Fingerprint — No Label Leakage
The phishing intent fingerprint is trained and generated using **out-of-fold cross-validation**. At inference, the fingerprint is *predicted*, never assumed. Any other approach would create label leakage that inflates evaluation metrics.

### 4. Hybrid Rule + ML Architecture
Pure ML misses deterministic red flags (OTP requests, IP URLs). Pure rules miss novel semantic phishing. The hybrid approach fuses D_rules feature vectors into Model C, and applies hard overrides (e.g., OTP request → always High-risk).

### 5. Code-Mixed Language Robustness
Indian phishing messages frequently mix English and Romanized Hindi. Model A2 uses **character n-grams** to capture morphological invariants. Model B uses **multilingual sentence embeddings** trained on 50+ languages including Hindi.

### 6. Four-Channel Scanning
Attackers use multiple vectors simultaneously. PhishGuard AI covers SMS (smishing), Email (traditional phishing + BEC), URL (link-only from QR codes/chats), and Attachment (malware delivery via macros/PEs).

---

## 24. Limitations & Ethical Disclaimer

> [!WARNING]
> **This is a model-based risk assessment, not proof of fraud.** PhishGuard AI assists in identifying suspicious patterns — it does not provide legal evidence or guarantee detection of all threats.

### Known Limitations
1. **Novel zero-day phishing** — campaigns designed to evade lexical/embedding models may score Genuine
2. **Image-based phishing** — OCR is not implemented; screenshots of phishing text are not analyzed
3. **Context blindness** — the model does not know if you expected this message
4. **Adversarial text attacks** — deliberate character substitution beyond the lookalike list may evade rules
5. **No live URL fetching** — the system does not follow redirects or render pages; only URL string is analyzed
6. **Language scope** — optimized for English and Romanized Hindi; other scripts may have reduced accuracy
7. **OSINT freshness** — brand registry and scam pattern database require manual updates for newly reported campaigns

### Ethical Use
PhishGuard AI is designed for **personal cybersecurity protection** only. It must not be used to:
- Build spam lists or profiling systems
- Retroactively accuse individuals of fraud without independent verification
- Replace human judgment or law enforcement investigation

---

*Report generated: October 2026 | PhishGuard AI v1.0.0 | "Detect before you click."*
