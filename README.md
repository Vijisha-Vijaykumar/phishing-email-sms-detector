# 🛡️ PhishGuard AI

### Explainable & Robust Phishing Detection for Email, SMS, URLs & Attachments

> **Detect before you click.**

PhishGuard AI is a privacy-focused, explainable cybersecurity system designed to detect phishing threats across **SMS, Email, URLs, and file attachments**.

It combines **Machine Learning, NLP, deterministic security rules, URL analysis, attachment inspection, OSINT intelligence, and explainable AI** to provide a risk assessment together with evidence explaining why an input was classified as suspicious.

---

## 🚀 Key Features

### 📱 1. SMS Phishing Detection

Analyzes SMS messages and sender information to detect common phishing and social-engineering patterns such as:

* Urgency and pressure
* Account suspension threats
* OTP requests
* Payment requests
* Reward/lottery scams
* Brand impersonation
* Suspicious links

### 📧 2. Email Phishing Detection

Analyzes:

* Email subject
* Sender address
* Email body
* URLs
* Social-engineering indicators
* Brand impersonation
* Credential and payment requests

### 🔗 3. URL Analysis

The URL analysis engine checks multiple indicators, including:

* IP-based URLs
* HTTP vs HTTPS
* URL shorteners
* Suspicious TLDs
* Punycode / IDN domains
* Typosquatting
* Subdomain injection
* Suspicious URL paths
* Trusted-domain comparison

### 📎 4. Attachment Security Analysis

Attachments are analyzed **statically** without executing them.

Supported file categories include:

* PDF
* DOC/DOCX
* XLS/XLSX
* PPT/PPTX
* ZIP/RAR
* EXE/DLL
* BAT
* PowerShell files

The scanner checks for:

* File type mismatches
* High entropy
* Macros
* Suspicious VBA patterns
* JavaScript in PDFs
* Embedded URLs
* Dangerous archive contents
* ZIP-bomb characteristics
* Suspicious PE imports

**Files are quarantined temporarily, analyzed, and deleted after analysis.**

---

## 🤖 Hybrid AI Detection

PhishGuard AI uses a combination of **Machine Learning + deterministic security rules**.

### Model hierarchy

```text
Model C
Semantic + Rule Features + Intent Fingerprint
        ↓
Model B
Multilingual Semantic Model
        ↓
Model A2
Word + Character N-Gram Model
        ↓
Model A
Baseline TF-IDF Model
```

The best available trained model is automatically selected.

### Models

| Model    | Approach                                      | Purpose                       |
| -------- | --------------------------------------------- | ----------------------------- |
| Model A  | Word TF-IDF + Logistic Regression             | Baseline                      |
| Model A2 | Word + Character TF-IDF + Logistic Regression | Robust lexical detection      |
| Model B  | Multilingual MiniLM embeddings + LR           | Semantic/code-mixed detection |
| Model C  | Semantic + rule features + intent fingerprint | Proposed hybrid model         |

The system is particularly designed to handle **English and Romanized Hindi/Hinglish** phishing patterns.

---

## 🧠 Phishing Intent Fingerprint

Instead of only answering:

> "Is this phishing?"

PhishGuard AI also analyzes **how the attacker is attempting to manipulate the victim**.

The system generates a 4-dimensional phishing intent fingerprint:

```text
Threat Vector
      +
Urgency
      +
Requested Action
      +
Demanded Asset
```

Example:

```text
Threat Vector     → Account Suspension
Urgency           → High
Requested Action  → Verify Identity
Demanded Asset    → Credential
```

This provides additional context about the social-engineering technique being used.

---

## 🔍 Explainable AI

PhishGuard AI does not simply return a classification.

It provides human-readable evidence explaining the decision.

Example indicators:

```text
⚠ High urgency detected
⚠ OTP sharing request detected
⚠ Suspicious URL detected
⚠ Brand impersonation detected
⚠ Sender/domain mismatch detected
```

The explanation layer uses **deterministic templates mapped to detected evidence**, rather than generating explanations through an external LLM.

---

## 🔐 Privacy by Design

Privacy is a core design principle.

### PII Masking

Before ML inference, sensitive information can be replaced with structural tokens:

```text
Phone number     → [PHONE]
Email address    → [EMAIL]
Card number      → [CARD]
Account number   → [ACCOUNT]
Transaction ref  → [TXN_REF]
```

### Privacy guarantees

* No external LLM is required for inference
* Message content is not sent to third-party AI services
* No persistent message database
* Attachment files are not stored after analysis
* Uploaded files are never executed
* OSINT queries use public domain/entity information rather than message bodies
* Repeat detection uses session-level in-memory data

---

## 🌐 OSINT & Web Intelligence

The system can optionally correlate extracted domains and entities with public threat intelligence.

Examples include:

* Brand/domain verification
* Scam advisory patterns
* Public threat intelligence
* URLhaus
* Suspicious TLD statistics
* Dynamic DNS indicators
* Free-hosting abuse indicators

OSINT findings can provide additional evidence and may increase the risk classification when strong indicators are detected.

---

## 🏗️ System Architecture

```text
                 USER INPUT
                     │
        ┌────────────┼────────────┐
        │            │            │
       SMS         EMAIL       URL / FILE
        │            │            │
        └────────────┼────────────┘
                     ▼
              React + Vite
              Frontend UI
                     │
                  HTTP/API
                     ▼
             FastAPI Backend
                     │
              Input Validation
                     │
                PII Masking
                     │
                   NER
                     │
              Rule Analysis
                     │
              URL Analysis
                     │
             OSINT Intelligence
                     │
             Rule Feature Vector
                     │
                ML Model
                     │
           Intent Fingerprint
                     │
                 XAI Layer
                     │
              Safety Advice
                     │
                     ▼
              Risk Assessment
              + Evidence
              + Explanation
```

---

## ⚙️ Tech Stack

### Frontend

* React 18
* Vite
* JavaScript
* Vanilla CSS
* Lucide React

### Backend

* Python 3.11
* FastAPI
* Uvicorn
* Pydantic

### Machine Learning / NLP

* scikit-learn
* sentence-transformers
* NumPy
* SciPy

### Data Engineering

* pandas
* PyArrow
* Parquet

### Security Analysis

* Python-based static file analysis
* URL heuristics
* Regex-based entity extraction
* OSINT / threat intelligence correlation

### Testing

* pytest

---

## 📡 API Endpoints

| Method | Endpoint              | Purpose                          |
| ------ | --------------------- | -------------------------------- |
| GET    | `/`                   | Project information              |
| GET    | `/health`             | Health check                     |
| GET    | `/docs`               | Swagger API documentation        |
| POST   | `/predict`            | Main phishing detection pipeline |
| POST   | `/fingerprint`        | Intent fingerprint               |
| POST   | `/extract`            | Entity extraction                |
| POST   | `/url-check`          | URL heuristic analysis           |
| POST   | `/sender-check`       | Sender analysis                  |
| POST   | `/web-intel`          | Web intelligence                 |
| POST   | `/analyze-attachment` | Attachment analysis              |
| POST   | `/analyze-url`        | Standalone URL analysis          |
| GET    | `/research/metrics`   | Model evaluation metrics         |
| GET    | `/samples`            | Demo samples                     |

---

## 🖥️ Frontend

The frontend provides a cybersecurity-themed dashboard with four scanning channels:

```text
PORT_01 → SMS
PORT_02 → EMAIL
PORT_03 → URL
PORT_04 → ATTACHMENT
```

### Dashboard includes

* Risk classification
* Confidence score
* Model information
* XAI reasoning
* Phishing intent fingerprint
* Threat indicators
* URL inspection
* Sender analysis
* Extracted entities
* Privacy/PII information
* OSINT intelligence
* Tactical safety recommendations

---

## 📊 Research & Evaluation

The project includes an evaluation pipeline for measuring:

* Accuracy
* Precision
* Recall
* F1-score
* Macro F1
* Confusion matrix
* Cross-validation performance

The project also includes checks for:

* Dataset overlap
* Train/test leakage
* Data quality
* Adversarial robustness

---

## 🧪 Testing

Run the test suite using:

```bash
pytest tests/ -v
```

The test suite covers:

* API endpoints
* Rule engine
* Entity extraction
* Attachment analysis
* Reputation analysis
* Data leakage

---

## 📁 Project Structure

```text
cyberhack/
│
├── backend/
│   └── app/
│       ├── main.py
│       ├── routes/
│       ├── rules/
│       └── services/
│
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── index.css
│       └── components/
│
├── scripts/
│   ├── train_baseline.py
│   ├── train_robust_lexical.py
│   ├── train_semantic.py
│   ├── train_fingerprint.py
│   ├── evaluate.py
│   └── data-processing scripts
│
├── data/
├── models/
├── reports/
├── tests/
├── config.yaml
└── README.md
```

---

## 🔄 Detection Workflow

```text
Input
  ↓
Validation
  ↓
PII Masking
  ↓
Entity Extraction
  ↓
Rule Analysis
  ↓
URL Analysis
  ↓
OSINT Intelligence
  ↓
ML Prediction
  ↓
Intent Fingerprint
  ↓
Explainable AI
  ↓
Safety Advice
  ↓
Final Risk Assessment
```

---

## ⚠️ Limitations

PhishGuard AI provides a **model-based risk assessment**, not proof of fraud.

Known limitations include:

* Novel zero-day phishing may evade detection
* Image-based phishing/OCR is not currently supported
* Context about whether a user expected a message is unavailable
* Advanced adversarial text manipulation may evade detection
* URLs are analyzed without rendering the destination webpage
* Language coverage is primarily focused on English and Romanized Hindi
* OSINT sources require periodic updates

---

## 🛡️ Ethical Disclaimer

PhishGuard AI is intended for **educational, research, and personal cybersecurity protection**.

It should not be used to:

* Profile individuals
* Build spam lists
* Accuse individuals of fraud without independent verification
* Replace human judgment or professional investigation

Detection results should always be independently verified before taking consequential action.

---

## 🎯 Project Goal

PhishGuard AI aims to combine **Data Science and Cybersecurity** into a practical phishing-analysis platform that is:

**Explainable · Privacy-focused · Multi-channel · Security-oriented · Research-driven**

> **Detect before you click.**

---

## 👩‍💻 Project

**PhishGuard AI — Phishing Email & SMS Detector**

Built as a student Data Science & Cybersecurity project.

**Version:** 1.0.0
**Date:** October 2026
