# PhishGuard AI — Model Card

**Version:** 1.0.0
**Generated:** Automated pipeline output
**Random Seed:** 42

## Model Overview

PhishGuard AI classifies Email and SMS messages into three risk categories:
- **Genuine** — No significant phishing indicators
- **Suspicious** — Some concerning signals but no direct credential/payment demand
- **High-risk** — Active phishing attempt with credential requests, threats, or off-platform payment demands

## Models

| Model | Description |
|---|---|
| Model A | Baseline: Word TF-IDF + Logistic Regression |
| Model A2 | Robust Lexical: Word + Char n-gram TF-IDF + LR |
| Model B | Semantic: Multilingual MiniLM Embeddings + LR |
| Model C | Proposed: Semantic + Predicted Phishing Intent Fingerprint + LR |

## Evaluation Results (Test Set)

> **Note:** Only results from actual trained models are displayed. No fabricated numbers.

| Model | Precision | Recall | F1 | FPR (Genuine) |
|---|---|---|---|---|
| Model A (Baseline) | 0.9316 | 0.9609 | 0.9457 | 0.0068 |
| Model A2 (Robust Lexical) | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Model B (Semantic) | 0.8594 | 0.9557 | 0.9011 | 0.0171 |
| Model C (Proposed: Semantic + Fingerprint) | 0.8594 | 0.9557 | 0.9011 | 0.0171 |


## Anti-Leakage Guarantee

- All variants sharing a `template_id` are strictly assigned to either train **or** test — never both.
- GroupKFold splitting on `template_id` was used to prevent paraphrase leakage.
- Ground-truth fingerprint labels (threat, urgency, action, credential/payment) are used **only** to train the fingerprint predictor. **They are never passed directly to the risk classifier.**
- Model C uses only **out-of-fold predicted fingerprints** during training and **test-time predicted fingerprints** during inference.

## Data Sources

| Dataset | License | Channel | Status |
|---|---|---|---|
| UCI SMS Spam Collection | CC BY 4.0 | SMS | VERIFIED |
| Mishra & Soni SMS Phishing | CC BY 4.0 | SMS | VERIFIED |
| Phishing Email Dataset (Baselight/Kaggle) | ODbL/Research | Email | VERIFIED |
| Enron Email Corpus (Curated) | Public Domain | Email | VERIFIED |
| Indian Scam SMS Synthetic | Apache 2.0 | SMS | VERIFIED |
| Mendeley Phishing URL Dataset | CC BY 4.0 | URL | VERIFIED |

## Limitations

- Phishing tactics evolve; models trained on historical data may miss novel patterns.
- Code-mixed Romanized spelling is highly variable and difficult to fully normalize.
- False positives are possible, especially for urgent-but-genuine messages (OTPs, utility bills).
- No voice, QR-code, or image phishing coverage.
- No automatic inbox or SMS reading integration.
- The system does not connect to real-time threat intelligence feeds by default.

## Disclaimer

> PhishGuard AI provides a model-based risk assessment, not legal proof of fraud.
> Always verify through an independently confirmed official channel before taking sensitive action.
