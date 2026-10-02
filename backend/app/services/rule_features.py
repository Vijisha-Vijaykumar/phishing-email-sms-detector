"""
PhishGuard AI — Deterministic Rule Feature Extractor
Converts rule-engine findings into a structured NumPy-compatible
binary/ordinal feature vector for use in Model C feature fusion.

D_rules  →  used in:  X_fused = [V_semantics || V_intent || D_rules]

Features are deterministic and reproducible — no ML model is used here.
"""

import numpy as np
from typing import Dict, List, Tuple

# Feature names in order (must stay stable for trained model compatibility)
RULE_FEATURE_NAMES: List[str] = [
    # Urgency
    "urgency_high",
    "urgency_medium",
    # Threat types
    "threat_account_suspension",
    "threat_service_disconnection",
    "threat_financial_loss",
    "threat_sim_deactivation",
    "threat_legal_action",
    "threat_parcel_hold",
    # Credential / payment
    "has_credential_request",
    "has_otp_share_instruction",
    "has_payment_request",
    "credential_and_payment",
    # Pressure
    "has_pressure_tactics",
    "has_fear_language",
    "has_reward_lure",
    "has_authority_language",
    # URL signals
    "has_any_url",
    "has_suspicious_url",
    "has_ip_url",
    "has_shortened_url",
    "has_http_only",
    "has_suspicious_tld",
    "has_lookalike_domain",
    "has_banking_path_keywords",
    "url_count_gt1",
    # Sender signals
    "sender_is_suspicious",
    "sender_mismatch",
    "sender_is_free_webmail",
    # Entity signals
    "has_bank_entity",
    "has_govt_entity",
    "has_phone_number",
    "has_monetary_amount",
    "has_otp_ref",
]

N_RULE_FEATURES = len(RULE_FEATURE_NAMES)


def build_rule_feature_vector(
    cues: Dict,
    url_checks: List[Dict],
    entities: Dict,
    sender_check: Dict,
) -> np.ndarray:
    """
    Build a 1-D binary/ordinal rule feature vector.

    Parameters
    ----------
    cues        : output of rule_engine.analyze_text
    url_checks  : list of url_analyzer.analyze_url_extended outputs
    entities    : output of ner_extractor.extract_entities
    sender_check: output of rule_engine.analyze_sender

    Returns
    -------
    np.ndarray of shape (N_RULE_FEATURES,), dtype float32
    """
    f: List[float] = []

    # ── Urgency ──────────────────────────────────────────────────────────────────
    urgency = cues.get("urgency_level", "Low")
    f.append(1.0 if urgency == "High"   else 0.0)
    f.append(1.0 if urgency == "Medium" else 0.0)

    # ── Threat ───────────────────────────────────────────────────────────────────
    threat = cues.get("detected_threat", "None")
    f.append(1.0 if threat == "Account suspension"     else 0.0)
    f.append(1.0 if threat == "Service disconnection"  else 0.0)
    f.append(1.0 if threat == "Financial loss"         else 0.0)
    f.append(1.0 if threat == "SIM deactivation"       else 0.0)
    f.append(1.0 if threat == "Legal action"           else 0.0)
    f.append(1.0 if threat == "Parcel/Delivery hold"   else 0.0)

    # ── Credential / payment ──────────────────────────────────────────────────────
    has_cred = cues.get("has_credential_request", False)
    has_otp  = cues.get("has_otp_share_instruction", False)
    has_pay  = cues.get("has_payment_request", False)
    f.append(1.0 if has_cred else 0.0)
    f.append(1.0 if has_otp  else 0.0)
    f.append(1.0 if has_pay  else 0.0)
    f.append(1.0 if has_cred and has_pay else 0.0)

    # ── Pressure / psychological ──────────────────────────────────────────────────
    f.append(1.0 if cues.get("has_pressure_tactics", False) else 0.0)
    f.append(1.0 if cues.get("has_fear_language",   False) else 0.0)
    f.append(1.0 if cues.get("has_reward_lure",     False) else 0.0)
    f.append(1.0 if cues.get("has_authority_language", False) else 0.0)

    # ── URL signals ───────────────────────────────────────────────────────────────
    urls     = cues.get("extracted_urls", []) or entities.get("urls", [])
    n_urls   = len(urls)
    sus_urls = [u for u in url_checks if u.get("is_suspicious")]
    ip_urls  = [u for u in url_checks if any("IP-based" in f_ for f_ in u.get("flags", []))]
    short_us = [u for u in url_checks if any("Shortened" in f_ for f_ in u.get("flags", []))]
    http_us  = [u for u in url_checks if not u.get("https", True)]
    tld_sus  = [u for u in url_checks if any("Suspicious TLD" in f_ for f_ in u.get("flags", []))]
    la_us    = [u for u in url_checks if any("typosquatting" in f_.lower() for f_ in u.get("flags", []))]
    bk_path  = [u for u in url_checks if any("Banking" in f_ for f_ in u.get("flags", []))]

    f.append(1.0 if n_urls > 0 else 0.0)
    f.append(1.0 if sus_urls   else 0.0)
    f.append(1.0 if ip_urls    else 0.0)
    f.append(1.0 if short_us   else 0.0)
    f.append(1.0 if http_us    else 0.0)
    f.append(1.0 if tld_sus    else 0.0)
    f.append(1.0 if la_us      else 0.0)
    f.append(1.0 if bk_path    else 0.0)
    f.append(1.0 if n_urls > 1 else 0.0)

    # ── Sender signals ────────────────────────────────────────────────────────────
    f.append(1.0 if sender_check.get("is_suspicious",    False) else 0.0)
    f.append(1.0 if sender_check.get("mismatch_detected",False) else 0.0)
    free_wm = any(
        "free webmail" in ind.lower()
        for ind in sender_check.get("indicators", [])
    )
    f.append(1.0 if free_wm else 0.0)

    # ── Entity signals ────────────────────────────────────────────────────────────
    f.append(1.0 if entities.get("banks_financial") else 0.0)
    f.append(1.0 if entities.get("government_bodies") else 0.0)
    f.append(1.0 if entities.get("phone_numbers") else 0.0)
    f.append(1.0 if entities.get("monetary_amounts") else 0.0)
    f.append(1.0 if entities.get("has_otp_ref") else 0.0)

    vec = np.array(f, dtype=np.float32)
    assert vec.shape == (N_RULE_FEATURES,), (
        f"Rule feature vector length mismatch: got {vec.shape}, expected ({N_RULE_FEATURES},)"
    )
    return vec


def get_rule_feature_names() -> List[str]:
    """Return the ordered list of rule feature names (for model introspection)."""
    return list(RULE_FEATURE_NAMES)
