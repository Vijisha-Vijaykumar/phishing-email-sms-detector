"""
PhishGuard AI — FastAPI Route: /predict and supporting endpoints

Architecture pipeline per request:
  Input Validation
    → PII Masking
    → NER / Entity Extraction
    → Deterministic Rule Engine
    → Extended URL Analysis
    → Rule Feature Vector (D_rules)
    → ML Prediction (Model A / A2 / B / C)
    → XAI / Guardrail Explanation
    → Safety Action Gate
    → JSON Response

No external LLM is called at any stage.
"""

import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List

from app.rules.rule_engine import (
    analyze_text, analyze_sender, build_evidence_list
)
from app.services.predictor import predict, predict_fingerprint, get_model_info
from app.services.repeat_check import check_and_increment
from app.utils.extractor import extract_message
from app.services.pii_masker import sanitize_and_mask
from app.services.ner_extractor import extract_entities
from app.services.url_analyzer import analyze_url_extended
from app.services.rule_features import build_rule_feature_vector
from app.services.xai_explainer import build_explanation, build_safety_advice_structured
from app.services.reputation_analyzer import analyze_web_reputation

router = APIRouter()

_MAX_TEXT_LEN    = 16_000   # characters — enough for a full email
_MAX_SUBJECT_LEN = 1_000
_MAX_SENDER_LEN  = 320


# ── Pydantic schemas ────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    channel: str = Field(..., description="'Email' or 'SMS'")
    text:    str = Field(..., description="Full message text")
    subject: Optional[str] = Field(default="", description="Email subject (empty for SMS)")
    sender:  Optional[str] = Field(default="", description="Sender identifier (optional)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "channel": "SMS",
                "text": "Your HDFC account will be suspended today. Verify KYC immediately: https://hdfc-kyc-update.in",
                "subject": "",
                "sender": "HDFCBK"
            }
        }
    )

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, v: str) -> str:
        if v not in ("Email", "SMS"):
            raise ValueError("channel must be 'Email' or 'SMS'")
        return v

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("text field must not be empty")
        if len(v) > _MAX_TEXT_LEN:
            raise ValueError(f"text exceeds maximum length of {_MAX_TEXT_LEN} characters")
        return v

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: Optional[str]) -> str:
        v = (v or "").strip()
        if len(v) > _MAX_SUBJECT_LEN:
            v = v[:_MAX_SUBJECT_LEN]
        return v

    @field_validator("sender")
    @classmethod
    def validate_sender(cls, v: Optional[str]) -> str:
        v = (v or "").strip()
        if len(v) > _MAX_SENDER_LEN:
            v = v[:_MAX_SENDER_LEN]
        return v


class PredictResponse(BaseModel):
    risk:             str
    risk_label:       Optional[str] = None
    confidence:       Optional[float] = None
    confidence_score: Optional[float] = None
    channel:          str
    model_used:       str
    entities:         dict
    cues:             dict
    fingerprint:      dict
    url_analysis:     list
    sender_check:     dict
    evidence:         list
    explanation:      str
    safety_advice:    list
    repeat_check:     dict
    latency_ms:       Optional[float]
    disclaimer:       str
    web_intel:        Optional[dict] = None


# ── Main endpoint ───────────────────────────────────────────────────────────────

@router.post("/predict", response_model=PredictResponse, tags=["Prediction"])
def predict_endpoint(req: PredictRequest):
    """
    Main phishing risk prediction endpoint.

    Pipeline:
    1. Input validation (Pydantic)
    2. PII masking
    3. NER entity extraction
    4. Deterministic rule analysis
    5. Extended URL analysis
    6. Rule feature vector (D_rules)
    7. ML prediction (best available model)
    8. Phishing intent fingerprint (predicted, never gold labels)
    9. XAI explanation
    10. Safety advice
    11. Evidence collection
    12. Repeat check
    """
    t_start = time.perf_counter()

    text    = req.text
    subject = req.subject or ""
    sender  = req.sender  or ""

    # ── Step 1: channel validation (already done by Pydantic validator)

    # ── Step 2: PII masking ────────────────────────────────────────────────────
    # masked_text is used for ML inference.
    # The original text is used for deterministic extraction (needed for URLs/phones).
    masked_text, pii_summary = sanitize_and_mask(text)

    # ── Step 3: NER entity extraction (original text) ─────────────────────────
    entities = extract_entities(text, subject=subject)

    # ── Step 4: Deterministic rule analysis ────────────────────────────────────
    cues        = analyze_text(text, sender=sender, subject=subject)
    sender_check = analyze_sender(sender, text=text)

    # ── Step 5: Extended URL analysis ─────────────────────────────────────────
    extracted_urls = entities.get("urls") or cues.get("extracted_urls", [])
    url_analysis   = [analyze_url_extended(url) for url in extracted_urls]

    # ── Step 5b: OSINT & Web Reputation Intelligence ──────────────────────────
    web_intel = analyze_web_reputation(
        extracted_urls=extracted_urls,
        entities=entities,
        sender_check=sender_check,
        subject=subject,
        sender=sender,
    )

    # ── Step 6: Rule feature vector ────────────────────────────────────────────
    rule_vec = build_rule_feature_vector(
        cues=cues,
        url_checks=url_analysis,
        entities=entities,
        sender_check=sender_check,
    )

    # ── Step 7: ML prediction (uses masked text for privacy, D_rules fused) ──
    ml_result  = predict(masked_text, rule_vec=rule_vec)
    risk       = ml_result["risk"]
    confidence = ml_result.get("confidence")
    model_used = ml_result.get("model_used", "N/A")

    # If web threat intelligence detected a confirmed scam campaign or deceptive impersonation, elevate to High-risk
    if web_intel.get("is_known_scam") or (web_intel.get("impersonation_alerts") and risk == "Genuine"):
        risk = "High-risk" if web_intel.get("is_known_scam") else "Suspicious"

    # ── Step 8: Phishing intent fingerprint (always predicted) ────────────────
    fingerprint = predict_fingerprint(masked_text)

    # ── Step 9: XAI explanation ────────────────────────────────────────────────
    explanation = build_explanation(
        risk=risk,
        cues=cues,
        url_checks=url_analysis,
        sender_check=sender_check,
        entities=entities,
        fingerprint=fingerprint,
    )
    if web_intel.get("impersonation_alerts"):
        explanation += f" OSINT Intelligence Alert: {web_intel['impersonation_alerts'][0]}"

    # ── Step 10: Safety advice (structured list) ──────────────────────────────
    safety_advice = build_safety_advice_structured(risk, cues, url_analysis)

    # ── Step 11: Evidence list ─────────────────────────────────────────────────
    evidence = build_evidence_list(cues, url_analysis)
    if sender_check.get("is_suspicious"):
        for ind in sender_check.get("indicators", []):
            if ind and not ind.startswith("Standard"):
                evidence.append(f"Sender: {ind}")
    for imp in web_intel.get("impersonation_alerts", []):
        evidence.append(f"Brand Impersonation: {imp}")
    for sc in web_intel.get("scam_bulletins", [])[:2]:
        evidence.append(f"Public Scam Alert: {sc}")
    if web_intel.get("is_verified_entity") and not web_intel.get("is_known_scam"):
        evidence.append("OSINT Verification: Official verified domain identified for recognized institution.")

    # ── Step 12: Repeat check ──────────────────────────────────────────────────
    repeat_info = check_and_increment(text)

    # ── Latency ───────────────────────────────────────────────────────────────
    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return PredictResponse(
        risk=risk,
        risk_label=risk,
        confidence=confidence,
        confidence_score=confidence,
        channel=req.channel,
        model_used=model_used,
        entities={
            "organizations":     entities.get("organizations", []),
            "banks_financial":   entities.get("banks_financial", []),
            "government_bodies": entities.get("government_bodies", []),
            "urls":              entities.get("urls", []),
            "phone_numbers":     entities.get("phone_numbers", []),
            "monetary_amounts":  entities.get("monetary_amounts", []),
            "dates_deadlines":   entities.get("dates_deadlines", []),
            "pii_detected":      pii_summary,
        },
        cues={
            "urgency":             cues.get("urgency_level", "Low"),
            "threat":              cues.get("detected_threat", "None"),
            "authority":           cues.get("has_authority_language", False),
            "fear":                cues.get("has_fear_language", False),
            "reward":              cues.get("has_reward_lure", False),
            "pressure":            cues.get("has_pressure_tactics", False),
            "credential_request":  cues.get("has_credential_request", False),
            "otp_share":           cues.get("has_otp_share_instruction", False),
            "payment_request":     cues.get("has_payment_request", False),
            "detected_action":     cues.get("detected_action", "None"),
        },
        fingerprint=fingerprint,
        url_analysis=url_analysis,
        sender_check=sender_check,
        evidence=evidence,
        explanation=explanation,
        safety_advice=safety_advice,
        repeat_check=repeat_info,
        latency_ms=latency_ms,
        disclaimer="This is a model-based risk assessment, not proof of fraud.",
        web_intel=web_intel,
    )


# ── Supporting endpoints ────────────────────────────────────────────────────────

@router.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "service": "PhishGuard AI"}


@router.get("/model-info", tags=["Models"])
def model_info():
    return get_model_info()


@router.post("/fingerprint", tags=["Fingerprint"])
def fingerprint_endpoint(req: PredictRequest):
    """Returns the predicted phishing intent fingerprint for a message."""
    masked, _ = sanitize_and_mask(req.text)
    return predict_fingerprint(masked)


@router.post("/extract", tags=["Extraction"])
def extract_endpoint(req: PredictRequest):
    """Extracts structured fields and entities from a message."""
    entities = extract_entities(req.text, subject=req.subject or "")
    legacy   = extract_message(req.text, subject=req.subject or "", sender=req.sender or "")
    return {**legacy, "entities": entities}


@router.post("/url-check", tags=["URL Analysis"])
def url_check_endpoint(body: dict):
    """Analyzes a single URL for phishing heuristics (extended)."""
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="url field required")
    return analyze_url_extended(url)


@router.post("/sender-check", tags=["Sender Analysis"])
def sender_check_endpoint(body: dict):
    """Analyzes sender identifier for spoofing or mismatch cues."""
    sender = body.get("sender", "")
    text   = body.get("text", "")
    return analyze_sender(sender, text=text)


@router.post("/repeat-check", tags=["Repeat Check"])
def repeat_check_endpoint(req: PredictRequest):
    """Checks how many times this message has been analyzed in this session."""
    return check_and_increment(req.text)


@router.get("/research/metrics", tags=["Research"])
def research_metrics():
    """Returns model evaluation results if experiments have been run."""
    import json
    from pathlib import Path
    results_dir = Path(__file__).resolve().parent.parent.parent.parent / "reports" / "results"

    models = {}
    for fname in ["model_a_results.json", "model_a2_results.json",
                  "model_b_results.json", "model_c_results.json",
                  "fingerprint_results.json"]:
        path = results_dir / fname
        if path.exists():
            with open(path) as f:
                models[fname.replace("_results.json", "")] = json.load(f)

    if not models:
        return {"message": "Results not available yet. Run training scripts first."}
    return {"results": models}


@router.post("/web-intel", tags=["Web Intelligence"])
def web_intel_endpoint(body: dict):
    """
    Performs OSINT, news threat intelligence, and brand authority checks
    on specified domains, sender addresses, or company names.
    """
    url = body.get("url", "")
    sender = body.get("sender", "")
    entity = body.get("entity", "")
    urls = [url] if url else body.get("urls", [])
    entities = {"organizations": [entity]} if entity else {}
    return analyze_web_reputation(
        extracted_urls=urls,
        entities=entities,
        sender=sender,
        subject=body.get("subject", "")
    )

