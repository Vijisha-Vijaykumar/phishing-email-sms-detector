"""
PhishGuard AI — Phishing Intent Fingerprint Predictor Training
Implements Section 19 & 20: Fingerprint predictor trained SEPARATELY from the risk classifier.
CRITICAL: Ground-truth fingerprint labels (threat, urgency, action, cred/pay) NEVER flow
directly into the risk classifier — only OUT-OF-FOLD predicted values do.

Trains four separate classifiers (one per fingerprint field):
- threat
- urgency
- requested_action
- credential_payment_request

Outputs:
- models/trained/fingerprint_predictors.pkl
- reports/results/fingerprint_results.json
"""

import os
import json
import pickle
import yaml
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models", "trained")
RESULTS_DIR = os.path.join(BASE_DIR, "reports", "results")
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

FINGERPRINT_FIELDS = [
    "threat",
    "urgency",
    "requested_action",
    "credential_payment_request"
]

FALLBACK_DEFAULTS = {
    "threat": "None",
    "urgency": "Low",
    "requested_action": "None",
    "credential_payment_request": "None"
}

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def train_fingerprint():
    print("=" * 70)
    print(" PhishGuard AI — Training Phishing Intent Fingerprint Predictor")
    print("=" * 70)
    
    cfg = load_config()
    seed = cfg["reproducibility"]["random_seed"]
    np.random.seed(seed)
    
    train_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "train.parquet"))
    test_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "test.parquet"))
    
    X_train_raw = train_df["text"].fillna("").astype(str)
    X_test_raw = test_df["text"].fillna("").astype(str)
    
    # Shared TF-IDF vectorizer for all fingerprint fields
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True,
        strip_accents="unicode",
        analyzer="word"
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)
    
    predictors = {"vectorizer": vectorizer}
    all_results = {}
    
    for field in FINGERPRINT_FIELDS:
        print(f"\nTraining fingerprint predictor for field: [{field}]")
        
        # Fill missing with 'None' label
        y_train_raw = train_df[field].fillna(FALLBACK_DEFAULTS[field]).astype(str)
        y_test_raw = test_df[field].fillna(FALLBACK_DEFAULTS[field]).astype(str)
        
        le = LabelEncoder()
        y_train = le.fit_transform(y_train_raw)
        y_test = le.transform(
            y_test_raw.map(lambda x: x if x in le.classes_ else FALLBACK_DEFAULTS[field])
        )
        
        clf = LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=seed,
            class_weight="balanced",
            solver="lbfgs",
            
        )
        clf.fit(X_train_tfidf, y_train)
        
        y_pred = clf.predict(X_test_tfidf)
        
        classes = le.classes_
        actual_labels = sorted(set(y_test.tolist() + y_pred.tolist()))
        actual_names = [classes[i] for i in actual_labels]
        report = classification_report(y_test, y_pred, labels=actual_labels, target_names=actual_names, output_dict=True, zero_division=0)
        
        macro_f1 = report.get("macro avg", {}).get("f1-score", 0.0)
        print(f"  Classes: {list(classes)}")
        print(f"  Macro F1: {macro_f1:.4f}")
        
        predictors[field] = {
            "classifier": clf,
            "label_encoder": le
        }
        all_results[field] = {
            "classes": classes.tolist(),
            "macro_f1": macro_f1,
            "report": report
        }
    
    # Save fingerprint predictor bundle
    model_path = os.path.join(MODELS_DIR, "fingerprint_predictors.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(predictors, f)
    print(f"\nSaved fingerprint predictors to: {model_path}")
    
    results_summary = {
        "model_name": "Phishing Intent Fingerprint Predictor",
        "note": "Fingerprint ground-truth labels are NEVER used as features in the risk classifier. Only out-of-fold predicted fingerprints are used in Model C.",
        "fields": all_results
    }
    results_path = os.path.join(RESULTS_DIR, "fingerprint_results.json")
    with open(results_path, "w") as f:
        json.dump(results_summary, f, indent=2)
    print(f"Saved fingerprint results to: {results_path}")
    print("=" * 70)
    return predictors, all_results

if __name__ == "__main__":
    train_fingerprint()
