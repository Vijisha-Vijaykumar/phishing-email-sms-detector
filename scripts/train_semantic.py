"""
PhishGuard AI — Model B & C: Semantic (MiniLM Embeddings) + Proposed Fingerprint Model
Implements Sections 21 & 22:
- MODEL B: Frozen multilingual-MiniLM embeddings + Logistic Regression
- MODEL C (Proposed): Model B + out-of-fold predicted phishing-intent fingerprint
  CRITICAL: Only PREDICTED fingerprint features are used in Model C — never gold labels.

Outputs:
- models/trained/model_b_semantic.pkl
- models/trained/model_c_proposed.pkl
- reports/results/model_b_results.json
- reports/results/model_c_results.json
"""

import os
import json
import pickle
import yaml
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GroupKFold
from sentence_transformers import SentenceTransformer

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models", "trained")
RESULTS_DIR = os.path.join(BASE_DIR, "reports", "results")
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

FINGERPRINT_FIELDS = ["threat", "urgency", "requested_action", "credential_payment_request"]
FALLBACK_DEFAULTS = {
    "threat": "None",
    "urgency": "Low",
    "requested_action": "None",
    "credential_payment_request": "None"
}

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def compute_metrics(y_true, y_pred, classes, model_name):
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

def train_semantic():
    print("=" * 70)
    print(" PhishGuard AI — Training Model B (Semantic) & Model C (Proposed)")
    print("=" * 70)
    
    cfg = load_config()
    seed = cfg["reproducibility"]["random_seed"]
    np.random.seed(seed)
    
    sem_cfg = cfg["models"]["semantic"]
    prop_cfg = cfg["models"]["proposed"]
    
    train_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "train.parquet"))
    test_df = pd.read_parquet(os.path.join(PROCESSED_DIR, "test.parquet"))
    
    print(f"\nLoading embedding model: {sem_cfg['embedding_model']}")
    embedder = SentenceTransformer(sem_cfg["embedding_model"])
    
    X_train_texts = train_df["text"].fillna("").astype(str).tolist()
    X_test_texts = test_df["text"].fillna("").astype(str).tolist()
    
    print("Encoding training embeddings...")
    X_train_emb = embedder.encode(
        X_train_texts,
        batch_size=sem_cfg["batch_size"],
        show_progress_bar=True,
        convert_to_numpy=True
    )
    print("Encoding test embeddings...")
    X_test_emb = embedder.encode(
        X_test_texts,
        batch_size=sem_cfg["batch_size"],
        show_progress_bar=True,
        convert_to_numpy=True
    )
    print(f"Embedding shape: {X_train_emb.shape}")
    
    le = LabelEncoder()
    y_train = le.fit_transform(train_df["risk_label"])
    y_test = le.transform(test_df["risk_label"])
    classes = le.classes_
    
    # -----------------------------------------------------------------------
    # MODEL B: Semantic embeddings only
    # -----------------------------------------------------------------------
    print("\n--- Model B: Semantic Embeddings Only ---")
    clf_b = LogisticRegression(
        C=sem_cfg["c_regularization"],
        max_iter=1000,
        random_state=seed,
        class_weight="balanced",
        solver="lbfgs",
        
    )
    clf_b.fit(X_train_emb, y_train)
    y_pred_b = clf_b.predict(X_test_emb)
    
    results_b = compute_metrics(y_test, y_pred_b, classes, "Model B — Semantic (MiniLM + LR)")
    print(f"  Macro F1: {results_b['overall']['macro_f1']:.4f}")
    print(f"  FPR on Genuine: {results_b['overall']['false_positive_rate_on_genuine']:.4f}")
    
    artifact_b = {
        "embedder_name": sem_cfg["embedding_model"],
        "classifier": clf_b,
        "label_encoder": le,
        "config": sem_cfg
    }
    model_b_path = os.path.join(MODELS_DIR, "model_b_semantic.pkl")
    with open(model_b_path, "wb") as f:
        pickle.dump(artifact_b, f)
    
    results_b_path = os.path.join(RESULTS_DIR, "model_b_results.json")
    with open(results_b_path, "w") as f:
        json.dump(results_b, f, indent=2)
    
    # -----------------------------------------------------------------------
    # MODEL C: Semantic + OUT-OF-FOLD PREDICTED Fingerprint Features
    # CRITICAL GUARANTEE: Only predicted (never gold) fingerprint values used
    # -----------------------------------------------------------------------
    print("\n--- Model C: Semantic + Predicted Fingerprint (Proposed) ---")
    print("  Building out-of-fold fingerprint predictions for training set...")
    
    fp_predictors_path = os.path.join(MODELS_DIR, "fingerprint_predictors.pkl")
    if not os.path.exists(fp_predictors_path):
        print("  [WARNING] fingerprint_predictors.pkl not found. Run train_fingerprint.py first.")
        print("  Skipping Model C training.")
        return results_b, None
    
    with open(fp_predictors_path, "rb") as f:
        fp_bundle = pickle.load(f)
    
    fp_vectorizer = fp_bundle["vectorizer"]
    
    # Compute out-of-fold fingerprint predictions for TRAINING set
    gkf = GroupKFold(n_splits=prop_cfg["out_of_fold_folds"])
    groups = train_df["template_id"].values
    
    fp_train_oof = np.zeros((len(train_df), len(FINGERPRINT_FIELDS)), dtype=np.float32)
    
    for fold_idx, (fold_train_idx, fold_val_idx) in enumerate(gkf.split(train_df, groups=groups)):
        fold_texts = train_df.iloc[fold_train_idx]["text"].fillna("").astype(str).tolist()
        val_texts = train_df.iloc[fold_val_idx]["text"].fillna("").astype(str).tolist()
        
        fold_tfidf = fp_vectorizer.transform(fold_texts)
        val_tfidf = fp_vectorizer.transform(val_texts)
        
        for field_idx, field in enumerate(FINGERPRINT_FIELDS):
            field_clf = fp_bundle[field]["classifier"]
            y_fold_field = train_df.iloc[fold_train_idx][field].fillna(FALLBACK_DEFAULTS[field]).astype(str)
            le_field = fp_bundle[field]["label_encoder"]
            
            y_fold_enc = le_field.transform(
                y_fold_field.map(lambda x: x if x in le_field.classes_ else FALLBACK_DEFAULTS[field])
            )
            
            # Refit predictor on fold-train portion  
            fold_clf = LogisticRegression(
                C=1.0, max_iter=500, random_state=seed,
                class_weight="balanced", solver="lbfgs"
            )
            if len(np.unique(y_fold_enc)) > 1:
                fold_clf.fit(fold_tfidf, y_fold_enc)
                oof_proba = fold_clf.predict_proba(val_tfidf)
                # Use predicted class index as numeric feature
                fp_train_oof[fold_val_idx, field_idx] = fold_clf.predict(val_tfidf).astype(np.float32)
    
    # Compute fingerprint predictions on TEST set (using full trained predictors)
    X_test_tfidf = fp_vectorizer.transform(X_test_texts)
    fp_test_pred = np.zeros((len(test_df), len(FINGERPRINT_FIELDS)), dtype=np.float32)
    
    for field_idx, field in enumerate(FINGERPRINT_FIELDS):
        field_clf = fp_bundle[field]["classifier"]
        fp_test_pred[:, field_idx] = field_clf.predict(X_test_tfidf).astype(np.float32)
    
    # Combine: embeddings + predicted fingerprint features
    X_train_c = np.hstack([X_train_emb, fp_train_oof])
    X_test_c = np.hstack([X_test_emb, fp_test_pred])
    
    clf_c = LogisticRegression(
        C=prop_cfg["c_regularization"],
        max_iter=1000,
        random_state=seed,
        class_weight="balanced",
        solver="lbfgs",
        
    )
    clf_c.fit(X_train_c, y_train)
    y_pred_c = clf_c.predict(X_test_c)
    
    results_c = compute_metrics(y_test, y_pred_c, classes, "Model C — Semantic + Predicted Fingerprint (Proposed)")
    print(f"  Macro F1: {results_c['overall']['macro_f1']:.4f}")
    print(f"  FPR on Genuine: {results_c['overall']['false_positive_rate_on_genuine']:.4f}")
    
    # Ablation comparison
    delta_f1 = results_c["overall"]["macro_f1"] - results_b["overall"]["macro_f1"]
    results_c["ablation_vs_model_b"] = {
        "note": "Honest fingerprint ablation: Model C vs Model B. Positive delta means fingerprint helped.",
        "delta_macro_f1": round(delta_f1, 4),
        "fingerprint_fields_used": FINGERPRINT_FIELDS,
        "anti_leakage": "Out-of-fold predicted fingerprints used for training; gold fingerprints NEVER used as risk classifier features."
    }
    
    artifact_c = {
        "embedder_name": prop_cfg["embedding_model"],
        "classifier": clf_c,
        "label_encoder": le,
        "fp_predictors_path": fp_predictors_path,
        "fingerprint_fields": FINGERPRINT_FIELDS,
        "config": prop_cfg
    }
    model_c_path = os.path.join(MODELS_DIR, "model_c_proposed.pkl")
    with open(model_c_path, "wb") as f:
        pickle.dump(artifact_c, f)
    
    results_c_path = os.path.join(RESULTS_DIR, "model_c_results.json")
    with open(results_c_path, "w") as f:
        json.dump(results_c, f, indent=2)
    
    print(f"\nModel B saved to: {model_b_path}")
    print(f"Model C saved to: {model_c_path}")
    print(f"Fingerprint ablation delta F1: {delta_f1:+.4f}")
    print("=" * 70)
    return results_b, results_c

if __name__ == "__main__":
    train_semantic()
