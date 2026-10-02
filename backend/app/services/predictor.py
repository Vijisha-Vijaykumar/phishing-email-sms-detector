"""
PhishGuard AI — ML Prediction Service
Loads trained models and performs runtime inference.

Model Hierarchy (best available wins):
  Model C — Semantic + Predicted Intent Fingerprint (+ D_rules if available)
  Model B — Frozen multilingual embeddings + LR
  Model A2 — Word + Char TF-IDF + LR
  Model A  — Word TF-IDF + LR (baseline)

CRITICAL:
  Model C always uses PREDICTED fingerprint features, never gold labels.
  D_rules (deterministic rule features) are fused if the model artifact
  was trained with them; otherwise falls back to Model C without D_rules.
"""

import os
import time
import pickle
import numpy as np
from typing import Dict, Optional, Tuple, List
from pathlib import Path

BASE_DIR   = Path(__file__).resolve().parent.parent.parent.parent
MODELS_DIR = BASE_DIR / "models" / "trained"

LABEL_DISPLAY = {
    "Genuine":   "Genuine",
    "Suspicious": "Suspicious",
    "High-risk": "High-risk"
}

_model_cache: Dict = {}


def _load(name: str):
    if name not in _model_cache:
        path = MODELS_DIR / name
        if not path.exists():
            return None
        with open(path, "rb") as f:
            _model_cache[name] = pickle.load(f)
    return _model_cache.get(name)


def _best_available_model():
    """Returns the best model artifact available on disk."""
    for fname, label in [
        ("model_c_proposed.pkl",       "Model C"),
        ("model_b_semantic.pkl",        "Model B"),
        ("model_a2_robust_lexical.pkl", "Model A2"),
        ("model_a_baseline.pkl",        "Model A"),
    ]:
        artifact = _load(fname)
        if artifact:
            return fname, label, artifact
    return None, None, None


# ── Model A / A2 ────────────────────────────────────────────────────────────────

def _predict_a(artifact, texts: List[str]) -> Tuple[List[str], List[float]]:
    vec = artifact["vectorizer"]
    clf = artifact["classifier"]
    le  = artifact["label_encoder"]
    X   = vec.transform(texts)
    preds = clf.predict(X)
    probs = clf.predict_proba(X)
    labels = le.inverse_transform(preds)
    confs  = [float(p.max()) for p in probs]
    return list(labels), confs


def _predict_a2(artifact, texts: List[str]) -> Tuple[List[str], List[float]]:
    from scipy.sparse import hstack
    wv  = artifact["word_vectorizer"]
    cv  = artifact["char_vectorizer"]
    clf = artifact["classifier"]
    le  = artifact["label_encoder"]
    X   = hstack([wv.transform(texts), cv.transform(texts)])
    preds  = clf.predict(X)
    probs  = clf.predict_proba(X)
    labels = le.inverse_transform(preds)
    confs  = [float(p.max()) for p in probs]
    return list(labels), confs


# ── Model B ─────────────────────────────────────────────────────────────────────

def _get_embedder(em_name: str):
    if "embedder" not in _model_cache:
        from sentence_transformers import SentenceTransformer
        _model_cache["embedder"] = SentenceTransformer(em_name)
    return _model_cache["embedder"]


def _predict_b(artifact, texts: List[str]) -> Tuple[List[str], List[float]]:
    try:
        clf     = artifact["classifier"]
        le      = artifact["label_encoder"]
        em_name = artifact["embedder_name"]
        embedder = _get_embedder(em_name)
        embs    = embedder.encode(
            texts, batch_size=32, show_progress_bar=False, convert_to_numpy=True
        )
        preds  = clf.predict(embs)
        probs  = clf.predict_proba(embs)
        labels = le.inverse_transform(preds)
        confs  = [float(p.max()) for p in probs]
        return list(labels), confs
    except Exception:
        return ["Genuine"] * len(texts), [0.5] * len(texts)


# ── Model C — Feature Fusion ────────────────────────────────────────────────────
# X_fused = [V_semantics || V_intent || D_rules]
# V_semantics = frozen multilingual sentence embedding
# V_intent    = predicted phishing-intent fingerprint
# D_rules     = deterministic URL/pattern/risk flags (optional, if model was trained with them)

def _predict_c(
    artifact,
    texts: List[str],
    rule_vecs: Optional[np.ndarray] = None,
) -> Tuple[List[str], List[float]]:
    try:
        clf       = artifact["classifier"]
        le        = artifact["label_encoder"]
        em_name   = artifact["embedder_name"]
        fp_fields = artifact.get("fingerprint_fields", [])
        uses_rules = artifact.get("uses_rule_features", False)

        embedder = _get_embedder(em_name)

        fp_bundle = _load("fingerprint_predictors.pkl")
        if not fp_bundle:
            return _predict_b(
                {"classifier": clf, "label_encoder": le, "embedder_name": em_name},
                texts,
            )

        # V_semantics
        embs = embedder.encode(
            texts, batch_size=32, show_progress_bar=False, convert_to_numpy=True
        )

        # V_intent (predicted fingerprint — never gold labels)
        fp_vec = fp_bundle["vectorizer"]
        X_tfidf = fp_vec.transform(texts)
        fp_feats = np.zeros((len(texts), len(fp_fields)), dtype=np.float32)
        for i, field in enumerate(fp_fields):
            bundle = fp_bundle.get(field)
            if bundle:
                fp_feats[:, i] = bundle["classifier"].predict(X_tfidf).astype(np.float32)

        # X_fused = [V_semantics || V_intent]
        X_fused = np.hstack([embs, fp_feats])

        # Optionally append D_rules if model was trained with them
        if uses_rules and rule_vecs is not None:
            if rule_vecs.ndim == 1:
                rule_vecs = rule_vecs.reshape(1, -1)
            # Pad or trim to match expected shape
            expected_rule_dim = artifact.get("rule_feature_dim", rule_vecs.shape[1])
            if rule_vecs.shape[1] != expected_rule_dim:
                # Dimension mismatch — skip D_rules gracefully
                pass
            else:
                X_fused = np.hstack([X_fused, rule_vecs])

        preds  = clf.predict(X_fused)
        probs  = clf.predict_proba(X_fused)
        labels = le.inverse_transform(preds)
        confs  = [float(p.max()) for p in probs]
        return list(labels), confs

    except Exception:
        return ["Genuine"] * len(texts), [0.5] * len(texts)


# ── Public API ──────────────────────────────────────────────────────────────────

FINGERPRINT_FALLBACK = {
    "threat":                    "None",
    "urgency":                   "Low",
    "requested_action":          "None",
    "credential_payment_request": "None",
}


def predict_fingerprint(text: str) -> Dict:
    """
    Predict the phishing intent fingerprint (4D) from text.
    Always uses the fingerprint predictor — never gold labels.
    """
    fp_bundle = _load("fingerprint_predictors.pkl")
    if not fp_bundle:
        return FINGERPRINT_FALLBACK.copy()

    fp_vec = fp_bundle["vectorizer"]
    X = fp_vec.transform([text])

    result = {}
    for field in ["threat", "urgency", "requested_action", "credential_payment_request"]:
        bundle = fp_bundle.get(field)
        if not bundle:
            result[field] = FINGERPRINT_FALLBACK[field]
            continue
        clf  = bundle["classifier"]
        le   = bundle["label_encoder"]
        pred = clf.predict(X)[0]
        result[field] = le.inverse_transform([pred])[0]

    return result


def predict(text: str, rule_vec: Optional[np.ndarray] = None) -> Dict:
    """
    Predict risk label and confidence for a single message.
    Uses the best available trained model.

    Parameters
    ----------
    text     : message text (PII-masked)
    rule_vec : optional D_rules feature vector from rule_features.build_rule_feature_vector
    """
    fname, model_label, artifact = _best_available_model()

    if artifact is None:
        return {
            "risk":       "Genuine",
            "confidence": None,
            "model_used": "No model available",
            "note":       "Models not trained yet. Run training pipeline first.",
        }

    # Dispatch to right predictor
    if "model_c" in fname:
        rule_vecs = rule_vec.reshape(1, -1) if rule_vec is not None else None
        labels, confs = _predict_c(artifact, [text], rule_vecs=rule_vecs)
    elif "model_b" in fname:
        labels, confs = _predict_b(artifact, [text])
    elif "model_a2" in fname:
        labels, confs = _predict_a2(artifact, [text])
    else:
        labels, confs = _predict_a(artifact, [text])

    return {
        "risk":       labels[0],
        "confidence": round(confs[0], 4),
        "model_used": model_label,
    }


def get_model_info() -> Dict:
    """Returns info on which models are loaded."""
    available = []
    for fname, label in [
        ("model_a_baseline.pkl",        "Model A — Baseline"),
        ("model_a2_robust_lexical.pkl",  "Model A2 — Robust Lexical"),
        ("model_b_semantic.pkl",         "Model B — Semantic"),
        ("model_c_proposed.pkl",         "Model C — Proposed"),
        ("fingerprint_predictors.pkl",   "Fingerprint Predictor"),
    ]:
        artifact = _load(fname)
        info: Dict = {"model": label, "available": artifact is not None}
        if artifact and fname == "model_c_proposed.pkl":
            info["uses_rule_features"] = artifact.get("uses_rule_features", False)
            info["feature_fusion"] = "V_semantics || V_intent || D_rules" if info["uses_rule_features"] else "V_semantics || V_intent"
        available.append(info)
    return {"models": available}
