"""
PhishGuard AI — Model A2: Robust Lexical (Word + Character n-gram TF-IDF + LR)
Implements Section 21: MODEL A2 — ROBUST LEXICAL MODEL
Character n-grams capture inconsistent Romanized spelling (karein/karen/kariye).
Outputs:
- models/trained/model_a2_robust_lexical.pkl
- reports/results/model_a2_results.json
"""

import os
import json
import pickle
import yaml
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
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

def compute_metrics(y_true, y_pred, label_encoder, classes, model_name):
    actual_labels = sorted(set(y_true.tolist() + y_pred.tolist()))
    actual_names = [classes[i] for i in actual_labels]
    report = classification_report(y_true, y_pred, labels=actual_labels, target_names=actual_names, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    
    genuine_class_idx = list(classes).index("Genuine") if "Genuine" in classes else 0
    genuine_actual = (y_true == genuine_class_idx)
    genuine_pred = (y_pred == genuine_class_idx)
    fp = ((~genuine_pred) & genuine_actual).sum()
    tn = (genuine_pred & genuine_actual).sum()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        "model_name": model_name,
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

def train_robust_lexical():
    print("=" * 70)
    print(" PhishGuard AI — Training Model A2: Robust Lexical (Word + Char TF-IDF + LR)")
    print("=" * 70)
    
    cfg = load_config()
    seed = cfg["reproducibility"]["random_seed"]
    np.random.seed(seed)
    
    model_cfg = cfg["models"]["robust_lexical"]
    
    train_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "train.parquet"))
    test_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "test.parquet"))
    
    X_train_raw = train_df["text"].fillna("").astype(str)
    X_test_raw = test_df["text"].fillna("").astype(str)
    
    le = LabelEncoder()
    y_train = le.fit_transform(train_df["risk_label"])
    y_test = le.transform(test_df["risk_label"])
    classes = le.classes_
    
    # Word-level TF-IDF
    word_vectorizer = TfidfVectorizer(
        ngram_range=tuple(model_cfg["word_ngram_range"]),
        max_features=model_cfg["word_max_features"],
        sublinear_tf=True,
        strip_accents="unicode",
        analyzer="word",
        min_df=1
    )
    
    # Character-level TF-IDF (crucial for code-mixed Romanized spelling variants)
    char_vectorizer = TfidfVectorizer(
        ngram_range=tuple(model_cfg["char_ngram_range"]),
        max_features=model_cfg["char_max_features"],
        sublinear_tf=True,
        analyzer=model_cfg.get("analyzer", "char_wb"),
        min_df=1
    )
    
    print("Fitting word-level TF-IDF...")
    X_train_word = word_vectorizer.fit_transform(X_train_raw)
    X_test_word = word_vectorizer.transform(X_test_raw)
    
    print("Fitting char-level TF-IDF...")
    X_train_char = char_vectorizer.fit_transform(X_train_raw)
    X_test_char = char_vectorizer.transform(X_test_raw)
    
    # Stack both feature matrices
    X_train_combined = hstack([X_train_word, X_train_char])
    X_test_combined = hstack([X_test_word, X_test_char])
    print(f"Combined feature matrix: {X_train_combined.shape[1]} features")
    
    clf = LogisticRegression(
        C=model_cfg["c_regularization"],
        max_iter=1000,
        random_state=seed,
        class_weight="balanced",
        solver="lbfgs",
        
    )
    clf.fit(X_train_combined, y_train)
    
    y_pred = clf.predict(X_test_combined)
    y_prob = clf.predict_proba(X_test_combined)
    
    results = compute_metrics(
        y_test, y_pred, le, classes,
        "Model A2 — Robust Lexical (Word + Char TF-IDF + LR)"
    )
    
    print(f"\nModel A2 Results:")
    print(f"  Macro F1:  {results['overall']['macro_f1']:.4f}")
    print(f"  Macro Precision: {results['overall']['macro_precision']:.4f}")
    print(f"  Macro Recall:    {results['overall']['macro_recall']:.4f}")
    print(f"  FPR on Genuine:  {results['overall']['false_positive_rate_on_genuine']:.4f}")
    
    artifact = {
        "word_vectorizer": word_vectorizer,
        "char_vectorizer": char_vectorizer,
        "classifier": clf,
        "label_encoder": le,
        "config": model_cfg
    }
    model_path = os.path.join(MODELS_DIR, "model_a2_robust_lexical.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(artifact, f)
    print(f"\nSaved Model A2 to: {model_path}")
    
    results_path = os.path.join(RESULTS_DIR, "model_a2_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved results to: {results_path}")
    print("=" * 70)
    return results

if __name__ == "__main__":
    train_robust_lexical()
