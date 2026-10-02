# PhishGuard AI Data Management Guide

## 1. Directory Structure
```
data/
├── raw/               # Immutable raw downloaded datasets
│   ├── uci_sms/       # UCI SMS Spam Collection
│   ├── mishra_soni/   # Mishra & Soni SMS Phishing Dataset
│   ├── enron/         # Enron Email Corpus sample
│   ├── email_phishing/# Baselight/Kaggle aggregated email corpus
│   └── url/           # Mendeley URL Dataset
├── interim/           # Standardized, pre-deduplicated candidate pools
├── processed/         # Cleaned, deduplicated, template-split train/test parquet files
├── custom/            # Controlled research templates (paraphrases, code-mixed variants, hard negatives)
└── audit/             # Audits, license verifications, and overlap records
```

## 2. Dataset Schema
Every processed record in `data/processed/` conforms to the canonical research schema:

- `message_id`: Unique identifier (e.g. `MSG_SMS_00124`)
- `channel`: `Email` or `SMS`
- `text`: Unified normalized text content (for Email: combined subject + body)
- `subject`: Email subject line (empty string for SMS)
- `body`: Email body text (SMS message for SMS)
- `sender`: Sender identifier, email address, shortcode, or phone (or empty if unknown)
- `language`: `English`, `Hinglish`, `Kanglish`, `Hindi`, `Kannada`
- `risk_label`: Target classification (`Genuine`, `Suspicious`, `High-risk`)
- `category`: Attack/communication category (e.g., `Banking/KYC`, `Utility/Electricity`, `Delivery/Courier`, `Transactional`, `Telecom`, `Workplace`)
- `threat`: Intent fingerprint threat field (`None`, `Account suspension`, `Service disconnection`, `Financial loss`, `SIM deactivation`, `Legal action`, `Parcel/Delivery hold`, `Other`)
- `urgency`: Intent fingerprint urgency field (`Low`, `Medium`, `High`)
- `requested_action`: Intent fingerprint primary action (`None`, `Pay`, `Click link`, `Verify identity`, `Share credential`, `Call number`, `Approve transaction`, `Reply/contact`)
- `credential_payment_request`: Intent fingerprint credential/payment indicator (`None`, `Credential`, `Payment`, `Both`)
- `template_id`: Unique template grouping identifier (e.g., `T_KYC_01`). Crucial for GroupKFold splitting!
- `variant_type`: `original`, `human_paraphrase`, `ai_paraphrase`, `hinglish_variant`, `kanglish_variant`, `hard_negative`, `near_miss`
- `generator`: `human`, `offline_ai_reviewed`, `benchmark_corpus`
- `prompt_version`: Prompt template identifier if AI generated, else `null`
- `human_reviewed`: Boolean flag verifying manual research review
- `source`: Dataset identifier (e.g., `uci`, `mishra_soni`, `enron`, `nazario`, `custom_research`)
- `source_corpus`: Granular sub-corpus identifier for email source-held-out evaluations
- `label_checked`: Verification status of ground truth label
- `label_2`: Independent second annotator label for Cohen's Kappa agreement evaluation
- `url_present`: Boolean indicating whether links are present
- `urgent_genuine`: Boolean flag denoting legitimate messages containing high-urgency language

## 3. Data Integrity & Anti-Leakage Policy

1. **Template-Level Grouping:** All variants sharing a `template_id` reside strictly on one side of the train/test split.
2. **Out-of-Fold Fingerprint Predictions:** Ground truth fingerprint annotations are NEVER provided to the risk classifier.
3. **Deduplication:** Hash-based exact duplicate removal and n-gram Jaccard near-duplicate screening prevent training contamination.
