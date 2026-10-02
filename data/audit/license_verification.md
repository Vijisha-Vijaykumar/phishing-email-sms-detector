# PhishGuard AI — Dataset License & Provenance Verification

**Document Status:** AUDITED & VERIFIED  
**Date of Audit:** October 2026  
**Auditor:** PhishGuard AI Research Pipeline  
**Compliance Directive:** No fabricated licenses, strict provenance tracking, and explicit label mapping rules.

---

## 1. Verified Datasets (usable_for_training = yes)

### 1.1 UCI SMS Spam Collection

- **Source URL:** https://archive.ics.uci.edu/dataset/228/
- **Date Checked:** 2026-10-02
- **License Shown:** Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Provenance:** Curated by Tiago A. Almeida, José María Gómez Hidalgo, and Akebo Yamakami (2011). Composed of 5,574 English SMS messages (4,827 ham, 747 spam).
- **Academic Research Permission:** Yes (CC BY 4.0 allows commercial, educational, and research use with attribution).
- **Redistribution Status:** Allowed with attribution.
- **Label Mapping Policy:** 
  - `ham` → `Genuine` candidate
  - `spam` → `REVIEW` (generic marketing/telecom spam excluded from High-risk phishing class; only verified fraudulent messages qualify for phishing class).
- **Overlap Mitigation:** Subjected to exact and near-duplicate matching against Mishra & Soni SMS Phishing dataset (`data/audit/uci_mishra_overlap.csv`).

### 1.2 Mishra & Soni SMS Phishing Dataset (Mendeley Data)

- **Source URL:** https://data.mendeley.com/datasets/f45bkkt8pr
- **Date Checked:** 2026-10-02
- **License Shown:** Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Provenance:** Published on Mendeley Data by Sonali Mishra and Dr. Ravindra Soni (2022). Contains 5,971 SMS records (4,844 ham, 489 spam, 638 smishing).
- **Academic Research Permission:** Yes (CC BY 4.0 permitted for research and development).
- **Redistribution Status:** Permitted with citation.
- **Label Mapping Policy:**
  - `ham` → `Genuine` candidate
  - `smishing` → `High-risk` candidate
  - `spam` → `REVIEW` / excluded from pure phishing model
- **Citation:** Mishra, S., & Soni, R. (2022). "SMS Phishing Dataset for Machine Learning and Pattern Recognition", Mendeley Data, V1, doi: 10.17632/f45bkkt8pr.1.

### 1.3 Phishing Email Dataset (Baselight / Kaggle Academic Compilation)

- **Source URL:** https://baselight.app/u/kaggle/dataset/naserabdullahalam_phishing_email_dataset
- **Date Checked:** 2026-10-02
- **License Shown:** Open Database License (ODbL) / Academic Research Use
- **Provenance:** Aggregated benchmark comprising José Nazario Phishing Corpus, Apache SpamAssassin Public Corpus, and Enron Email Corpus.
- **Academic Research Permission:** Yes, for academic machine learning research.
- **Redistribution Status:** Permitted under ODbL with source attribution.
- **Label Mapping Policy:**
  - Label `1` (Phishing) → `High-risk` candidate
  - Label `0` (Safe/Ham) → `Genuine` candidate
- **Methodological Guardrail:** `source_corpus` is tagged on every message to enable source-held-out cross-corpus evaluation, ensuring the classifier does not merely memorize stylistic artifacts of specific corpora.

### 1.4 Enron Email Corpus (Curated Subsample)

- **Source URL:** https://www.cs.cmu.edu/~enron/
- **Date Checked:** 2026-10-02
- **License Shown:** Public Domain / FERC Public Record
- **Provenance:** Federal Energy Regulatory Commission public investigation archive, cleaned and structured by Dr. William Cohen and CMU researchers.
- **Academic Research Permission:** Yes (widely accepted benchmark for legitimate corporate communication).
- **Redistribution Status:** Public Domain.
- **Label Mapping Policy:** All Enron messages are mapped to `Genuine` candidate. No phishing label is ever assigned to Enron records.

### 1.5 Indian Scam SMS Synthetic Audited Dataset (Hugging Face)

- **Source URL:** https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited
- **Date Checked:** 2026-10-02
- **License Shown:** Apache 2.0
- **Provenance:** Curated by Ridham115 on Hugging Face. Contains code-mixed Indian SMS scam patterns and legitimate service alerts.
- **Academic Research Permission:** Yes (Apache 2.0).
- **Data Integrity Rule:** Tagged with `source_type = synthetic`. Used strictly for Indian scam patterns and code-mixed training. NOT permitted as the primary held-out test set to avoid LLM synthetic distribution bias.

### 1.6 Mendeley Phishing URL Dataset

- **Source URL:** https://data.mendeley.com/datasets/vfszbj9b36
- **Date Checked:** 2026-10-02
- **License Shown:** CC BY 4.0
- **Provenance:** Mendeley Data (73,575 URLs labeled as `bad` or `good`).
- **Academic Research Permission:** Yes.
- **Isolation Policy:** Evaluated strictly in the URL analysis subsystem. Never mixed into message text embeddings or text classifier models.

---

## 2. Conditional & Excluded Sources (usable_for_training = no / pending)

| Dataset | Status | Reason & Action |
|---|---|---|
| **Smishtank SMS** | `PENDING_VERIFICATION` | Preprint under review; license terms pending formal confirmation. |
| **Indian Multilingual Scam/Ham (14 Languages)** | `PENDING_VERIFICATION` | Translation provenance undergoing manual validation before ingest. |
| **Indian Cyber Scam PhoneCall Hinglish** | `EXCLUDED` | Audio call transcripts violate project boundary (SMS + Email only). |
| **Multilingual Phishing (Gupta7050)** | `PENDING_VERIFICATION` | GitHub repository lacks an explicit OSI or Creative Commons license file. |
| **ScamShield Dataset** | `PENDING_VERIFICATION` | Research-only status; kept as comparative reference, excluded from primary split. |
| **OpenPhish Live Feed** | `OPTIONAL` | Academic registration required; system operates deterministically without external API dependency. |
