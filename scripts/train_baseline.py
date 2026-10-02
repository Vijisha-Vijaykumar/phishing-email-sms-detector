"""
PhishGuard AI — Model A: Baseline Lexical TF-IDF + Logistic Regression
Implements Section 21: MODEL A — BASELINE
Word TF-IDF + Logistic Regression for a simple lexical baseline.
Outputs:
- models/trained/model_a_baseline.pkl
- reports/results/model_a_results.json
"""

import os
import json
import pickle
import yaml
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix
from sklearn.preprocessing import LabelEncoder

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models", "trained")
RESULTS_DIR = os.path.join(BASE_DIR, "reports", "results")
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def compute_metrics(y_true, y_pred, y_prob, label_encoder, classes):
    """Compute precision, recall, F1, and FPR for genuine class vs. rest."""
    actual_labels = sorted(set(y_true.tolist() + y_pred.tolist()))
    actual_names = [classes[i] for i in actual_labels]
    report = classification_report(y_true, y_pred, labels=actual_labels, target_names=actual_names, output_dict=True, zero_division=0)
    
    # False-positive rate: genuine messages incorrectly flagged as phishing
    genuine_class_idx = list(classes).index("Genuine") if "Genuine" in classes else 0
    cm = confusion_matrix(y_true, y_pred)
    
    # FPR = FP / (FP + TN)  — for genuine class vs rest
    genuine_actual = (y_true == genuine_class_idx)
    genuine_pred = (y_pred == genuine_class_idx)
    fp = ((~genuine_pred) & genuine_actual).sum()
    tn = (genuine_pred & genuine_actual).sum()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        "model_name": "Model A — Baseline (Word TF-IDF + LR)",
        "classes": classes.tolist() if hasattr(classes, 'tolist') else list(classes),
        "overall": {
            "accuracy": report.get("accuracy", 0.0),
            "macro_precision": report.get("macro avg", {}).get("precision", 0.0),
            "macro_recall": report.get("macro avg", {}).get("recall", 0.0),
            "macro_f1": report.get("macro avg", {}).get("f1-score", 0.0),
            "false_positive_rate_on_genuine": round(float(fpr), 4)
        },
        "per_class": report,
        "confusion_matrix": cm.tolist()
    }

def train_baseline():
    print("=" * 70)
    print(" PhishGuard AI — Training Model A: Baseline (Word TF-IDF + LR)")
    print("=" * 70)
    
    cfg = load_config()
    seed = cfg["reproducibility"]["random_seed"]
    np.random.seed(seed)
    
    model_cfg = cfg["models"]["baseline"]
    
    train_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "train.parquet"))
    test_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "test.parquet"))
    
    print(f"Train: {len(train_df)} records | Test: {len(test_df)} records")
    print(f"Train label distribution: {dict(train_df['risk_label'].value_counts())}")
    
    X_train = train_df["text"].fillna("").astype(str)
    X_test = test_df["text"].fillna("").astype(str)
    
    le = LabelEncoder()
    y_train = le.fit_transform(train_df["risk_label"])
    y_test = le.transform(test_df["risk_label"])
    classes = le.classes_
    
    print(f"Classes: {classes}")
    
    # TF-IDF
    vectorizer = TfidfVectorizer(
        ngram_range=tuple(model_cfg["ngram_range"]),
        max_features=model_cfg["max_features"],
        sublinear_tf=model_cfg["sublinear_tf"],
        strip_accents="unicode",
        min_df=1,
        analyzer="word"
    )
    
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Logistic Regression
    clf = LogisticRegression(
        C=model_cfg["c_regularization"],
        max_iter=1000,
        random_state=seed,
        class_weight="balanced",
        solver="lbfgs",
        
    )
    clf.fit(X_train_tfidf, y_train)
    
    y_pred = clf.predict(X_test_tfidf)
    y_prob = clf.predict_proba(X_test_tfidf)
    
    results = compute_metrics(y_test, y_pred, y_prob, le, classes)
    
    print(f"\nModel A Results:")
    print(f"  Macro F1:  {results['overall']['macro_f1']:.4f}")
    print(f"  Macro Precision: {results['overall']['macro_precision']:.4f}")
    print(f"  Macro Recall:    {results['overall']['macro_recall']:.4f}")
    print(f"  FPR on Genuine:  {results['overall']['false_positive_rate_on_genuine']:.4f}")
    
    # Save model artifacts
    artifact = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "label_encoder": le,
        "config": model_cfg
    }
    model_path = os.path.join(MODELS_DIR, "model_a_baseline.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(artifact, f)
    print(f"\nSaved Model A to: {model_path}")
    
    results_path = os.path.join(RESULTS_DIR, "model_a_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved results to: {results_path}")
    print("=" * 70)
    return results

if __name__ == "__main__":
    train_baseline()
